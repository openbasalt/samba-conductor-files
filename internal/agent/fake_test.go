package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/openbasalt/samba-conductor-files/internal/samba"
	"github.com/openbasalt/samba-conductor-files/internal/sddl"
)

const testDom = "S-1-5-21-100-200-300"

type sidInfo struct {
	name string
	kind int
}

// fakeSamba is an in-memory Samba: registry configuration, share ACLs,
// NT ACLs, winbind names. Its *Args methods are samba.Tools' own (embedded),
// so the commands are exactly the real ones; RunArgs interprets them.
type fakeSamba struct {
	samba.Tools
	mu       sync.Mutex
	role     string
	smbconf  []samba.Section
	registry []samba.Section
	sharesec map[string]string
	ntacl    map[string]string
	sids     map[string]sidInfo
	ran      []string
	failOn   string
	reloads  int
}

func newFake() *fakeSamba {
	return &fakeSamba{
		Tools:    samba.Tools{P: samba.DefaultPaths()},
		role:     "member server",
		smbconf:  []samba.Section{{Name: "legacy", Params: [][2]string{{"path", "/srv/legacy"}}}},
		sharesec: map[string]string{},
		ntacl:    map[string]string{},
		sids: map[string]sidInfo{
			testDom + "-4105": {`LAB\Engineering`, samba.SidGroup},
			testDom + "-4106": {`LAB\Sales`, samba.SidGroup},
			testDom + "-4116": {`LAB\Helpdesk`, samba.SidAlias},
			testDom + "-512":  {`LAB\Domain Admins`, samba.SidGroup},
			testDom + "-1105": {`LAB\user0001`, samba.SidUser},
		},
	}
}

func (f *fakeSamba) Registry(context.Context) ([]samba.Section, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.registry), nil
}

func (f *fakeSamba) Effective(context.Context) ([]samba.Section, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []samba.Section{{Name: "global", Params: [][2]string{{"vfs objects", "acl_xattr"}}}}
	out = append(out, f.smbconf...)
	return append(out, f.registry...), nil
}

func (f *fakeSamba) Parameter(_ context.Context, name string) (string, error) {
	switch name {
	case "server role":
		return f.role, nil
	case "security":
		return "ADS", nil
	case "vfs objects":
		return "acl_xattr", nil
	}
	return "", errors.New("unknown parameter")
}

func (f *fakeSamba) Version(context.Context) (string, error) { return "4.22.11-Debian", nil }

func (f *fakeSamba) exists(name string) bool {
	return slices.ContainsFunc(append(slices.Clone(f.smbconf), f.registry...), func(s samba.Section) bool { return strings.EqualFold(s.Name, name) })
}

func (f *fakeSamba) ShareSecView(_ context.Context, share string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.exists(share) {
		return "", errors.New("Invalid sharename: " + share)
	}
	if s, ok := f.sharesec[strings.ToLower(share)]; ok {
		return s, nil
	}
	return "D:(A;;FA;;;WD)", nil
}

func (f *fakeSamba) NTACLGet(_ context.Context, p string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.ntacl[p]; ok {
		return s, nil
	}
	if st, err := os.Stat(p); err != nil || !st.IsDir() {
		return "", fmt.Errorf("no such directory %s", p)
	}
	return "O:S-1-22-1-0G:S-1-22-2-0D:(A;;FA;;;S-1-22-1-0)(A;;0x1200a9;;;WD)", nil
}

func (f *fakeSamba) LookupSID(_ context.Context, sid string) (string, int, error) {
	if i, ok := f.sids[sid]; ok {
		return i.name, i.kind, nil
	}
	return "", 0, errors.New("WBC_ERR_DOMAIN_NOT_FOUND")
}

func (f *fakeSamba) Domain(context.Context) (samba.DomainInfo, error) {
	return samba.DomainInfo{NetBIOS: "LAB", Realm: "LAB.TEST", SID: testDom}, nil
}

func (f *fakeSamba) TrustOK(context.Context) error { return nil }

func (f *fakeSamba) StatusJSON(context.Context) ([]byte, error) {
	return []byte(`{"sessions": {}, "tcons": {}, "open_files": {}}`), nil
}

func (f *fakeSamba) RunArgs(_ context.Context, argv []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.Join(argv, " ")
	f.ran = append(f.ran, line)
	if f.failOn != "" && strings.Contains(line, f.failOn) {
		return errors.New("simulated failure")
	}
	switch filepath.Base(argv[0]) {
	case "net":
		switch {
		case len(argv) == 5 && argv[1] == "conf" && argv[2] == "import":
			b, err := os.ReadFile(argv[3])
			if err != nil {
				return err
			}
			secs := samba.ParseConf(string(b))
			if len(secs) != 1 || secs[0].Name != argv[4] {
				return errors.New("import: one section named like the share expected")
			}
			f.registry = slices.DeleteFunc(f.registry, func(s samba.Section) bool { return strings.EqualFold(s.Name, argv[4]) })
			f.registry = append(f.registry, secs[0])
			return nil
		case len(argv) == 4 && argv[1] == "conf" && argv[2] == "delshare":
			n := len(f.registry)
			f.registry = slices.DeleteFunc(f.registry, func(s samba.Section) bool { return strings.EqualFold(s.Name, argv[3]) })
			if n == len(f.registry) {
				return errors.New("SBC_ERR_NO_SUCH_SERVICE")
			}
			return nil
		}
	case "sharesec":
		if !f.exists(argv[1]) {
			return errors.New("Invalid sharename")
		}
		switch {
		case strings.HasPrefix(argv[2], "--replace="):
			var b strings.Builder
			b.WriteString("D:")
			for _, e := range strings.Split(strings.TrimPrefix(argv[2], "--replace="), ",") {
				sid, rest, _ := strings.Cut(e, ":")
				mask := map[string]string{"ALLOWED/0/FULL": "FA", "ALLOWED/0/CHANGE": "0x1301ff", "ALLOWED/0/READ": "0x1200a9"}[rest]
				if mask == "" {
					return errors.New("bad ACL " + e)
				}
				b.WriteString("(A;;" + mask + ";;;" + sid + ")")
			}
			f.sharesec[strings.ToLower(argv[1])] = b.String()
			return nil
		case argv[2] == "--delete":
			delete(f.sharesec, strings.ToLower(argv[1]))
			return nil
		}
	case "samba-tool":
		if len(argv) == 7 && argv[1] == "ntacl" && argv[2] == "set" && argv[4] == "--" {
			if _, err := sddl.Parse(argv[5], testDom); err != nil {
				return err
			}
			// Samba prints aliases back; store the descriptor as written.
			f.ntacl[argv[6]] = argv[5]
			return nil
		}
	case "smbcontrol":
		f.reloads++
		return nil
	}
	return fmt.Errorf("fake: unexpected command %q", line)
}

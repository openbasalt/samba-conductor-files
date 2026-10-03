package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-files/filesapi"
	"github.com/openbasalt/samba-conductor-files/internal/audit"
	"github.com/openbasalt/samba-conductor-files/internal/config"
	"github.com/openbasalt/samba-conductor-files/internal/fsguard"
	"github.com/openbasalt/samba-conductor-files/internal/samba"
)

var actor = filesapi.Actor{User: "lab.admin", SID: testDom + "-1104", Session: "0123456789abcdef", IP: "10.93.0.10"}

type env struct {
	a     *Agent
	f     *fakeSamba
	root  string
	state string
	pin   string // a pinned client key
	n     int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	_ = os.Chmod(base, 0o755)
	root := filepath.Join(base, "shares")
	state := filepath.Join(base, "state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	smbConf := filepath.Join(base, "smb.conf")
	_ = os.WriteFile(smbConf, []byte("[global]\n\tsecurity = ADS\n\tinclude = registry\n"), 0o644)
	cfg := config.Default()
	cfg.Server.Name = "fs1.lab.test"
	cfg.Shares.Roots = []string{root}
	cfg.State.Dir, cfg.State.SmbConf = state, smbConf
	id, err := filesapi.LoadOrCreateIdentity(state, "fs1")
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(filepath.Join(state, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	f := newFake()
	a := New(Options{Config: cfg, Samba: f, Guard: fsguard.Guard{Roots: cfg.Shares.Roots, Owner: os.Getuid()},
		Trust: NewTrust(state, 5), Audit: al, ID: id, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"})
	e := &env{a: a, f: f, root: root, state: state, pin: "sha256:" + strings.Repeat("P", 43)}
	tok, _, err := a.trust.NewCode(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.trust.Enroll(tok, e.pin, "conductor-test", "test"); err != nil {
		t.Fatal(err)
	}
	return e
}

// call runs one request through Handle with the pinned key.
func (e *env) call(t *testing.T, op filesapi.Op, params filesapi.Params, out any) error {
	t.Helper()
	e.n++
	req, err := filesapi.NewRequest(fmt.Sprintf("test-%06d", e.n), op, actor, params)
	if err != nil {
		return err
	}
	return filesapi.DecodeResult(e.a.Handle(context.Background(), e.pin, "test", req), out)
}

func (e *env) must(t *testing.T, op filesapi.Op, params filesapi.Params, out any) {
	t.Helper()
	if err := e.call(t, op, params, out); err != nil {
		t.Fatalf("%s: %v", op, err)
	}
}

func wantCode(t *testing.T, err error, code filesapi.ErrorCode) *filesapi.Error {
	t.Helper()
	var e *filesapi.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
	return e
}

func (e *env) spec() filesapi.ShareSpec {
	return filesapi.ShareSpec{Name: "eng", Path: filepath.Join(e.root, "eng"), CreateDir: true, Comment: "Engineering",
		Browseable: true, Access: []filesapi.Grant{{SID: testDom + "-4105", Level: filesapi.LevelModify}}}
}

func TestShareLifecycle(t *testing.T) {
	e := newEnv(t)
	spec := e.spec()
	var st filesapi.Status
	e.must(t, filesapi.OpStatus, nil, &st)
	if !st.Ready() || st.DomainSID != testDom {
		t.Fatalf("status %+v", st)
	}

	var pl filesapi.Plan
	e.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: spec, Create: true}, &pl)
	want := []string{
		"# create the folder " + spec.Path + " (owner root:root, mode 0700, no symbolic links followed)",
		"/usr/bin/samba-tool ntacl set --use-s3fs -- 'O:S-1-5-32-544G:S-1-5-32-544D:PAI(A;OICI;0x001f01ff;;;S-1-5-18)(A;OICI;0x001f01ff;;;S-1-5-32-544)(A;OICI;0x001f01ff;;;" + testDom + "-512)(A;OICI;0x001301bf;;;" + testDom + "-4105)' " + spec.Path,
		"/usr/bin/net conf import " + e.state + "/import/eng.conf eng",
		"/usr/bin/sharesec eng --replace=S-1-5-32-544:ALLOWED/0/FULL," + testDom + "-512:ALLOWED/0/FULL," + testDom + "-4105:ALLOWED/0/CHANGE",
		"/usr/bin/smbcontrol smbd reload-config",
	}
	if strings.Join(pl.Commands, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(pl.Commands, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(pl.Section, "\tconductor-files:managed = yes\n") || pl.SectionBefore != "" || pl.Kind != "create" {
		t.Fatalf("plan %+v", pl)
	}
	if len(pl.NTACL.After) != 4 || pl.NTACL.After[3].Name != `LAB\Engineering` || pl.NTACL.After[3].Rights != "modify" {
		t.Fatalf("NT ACL after %+v", pl.NTACL.After)
	}
	if _, err := os.Stat(spec.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a plan must not write")
	}
	if len(e.f.ran) != 0 {
		t.Fatalf("a plan must not run commands: %v", e.f.ran)
	}

	wantCode(t, e.call(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: spec, Create: true, Digest: strings.Repeat("a", 64)}, nil), filesapi.CodeConflict)
	var ar filesapi.ApplyResult
	e.must(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: spec, Create: true, Digest: pl.Digest}, &ar)
	if len(ar.Steps) != 5 || e.f.reloads != 1 {
		t.Fatalf("apply %+v", ar)
	}
	if st, err := os.Stat(spec.Path); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("folder %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(e.state, "import", "eng.conf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the import file must be removed")
	}
	// Creating it again is refused; planning the same spec as an update is a no-op.
	wantCode(t, e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: spec, Create: true}, nil), filesapi.CodeInvalid)
	same := spec
	same.CreateDir = false
	e.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: same}, &pl)
	if !pl.NoChange || len(pl.Commands) != 0 {
		t.Fatalf("no-op plan %+v", pl.Commands)
	}

	// The spec comes back from the share.
	var d filesapi.ShareDetail
	e.must(t, filesapi.OpShareGet, filesapi.ShareNameParams{Name: "ENG"}, &d)
	if !d.Managed || d.Spec == nil || len(d.Spec.Access) != 1 || d.Spec.Access[0].Level != filesapi.LevelModify || d.Spec.Access[0].Name != `LAB\Engineering` {
		t.Fatalf("detail %+v spec %+v", d, d.Spec)
	}

	// Update: Engineering read, Sales full, recycle bin; only what changed runs.
	upd := same
	upd.Access = []filesapi.Grant{{SID: testDom + "-4106", Level: filesapi.LevelFull}, {SID: testDom + "-4105", Level: filesapi.LevelRead}}
	e.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: upd}, &pl)
	if len(pl.Commands) != 3 || !pl.NTACL.Changed || !pl.ShareACL.Changed || len(pl.Warnings) == 0 {
		t.Fatalf("access update plan %v", pl.Commands)
	}
	e.must(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: upd, Digest: pl.Digest}, &ar)
	upd.RecycleBin = true
	e.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: upd}, &pl)
	if len(pl.Commands) != 2 || !strings.Contains(pl.Commands[0], "net conf import") ||
		!strings.Contains(pl.Section, "vfs objects = acl_xattr recycle") || !strings.Contains(pl.Section, "recycle:repository = .recycle/%U") {
		t.Fatalf("option update plan %v\n%s", pl.Commands, pl.Section)
	}
	e.must(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: upd, Digest: pl.Digest}, &ar)
	e.must(t, filesapi.OpShareGet, filesapi.ShareNameParams{Name: "eng"}, &d)
	if !d.Spec.RecycleBin || len(d.Spec.Access) != 2 {
		t.Fatalf("spec after update %+v", d.Spec)
	}

	// A change behind the plan's back makes the apply conflict.
	e.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: same}, &pl)
	e.f.ntacl[spec.Path] = "O:BAG:BAD:PAI(A;OICI;FA;;;SY)"
	wantCode(t, e.call(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: same, Digest: pl.Digest}, nil), filesapi.CodeConflict)

	// Removal keeps the folder and drops the share ACL first.
	var rp filesapi.Plan
	e.must(t, filesapi.OpShareRemovePlan, filesapi.ShareNameParams{Name: "eng"}, &rp)
	if rp.Kind != "remove" || !strings.Contains(rp.Commands[0], "sharesec eng --delete") || !strings.Contains(rp.Commands[1], "net conf delshare eng") {
		t.Fatalf("remove plan %v", rp.Commands)
	}
	wantCode(t, e.call(t, filesapi.OpShareRemove, filesapi.ShareNameParams{Name: "eng"}, nil), filesapi.CodeInvalid)
	e.must(t, filesapi.OpShareRemove, filesapi.ShareNameParams{Name: "eng", Digest: rp.Digest}, &ar)
	if len(e.f.registry) != 0 || len(e.f.sharesec) != 0 {
		t.Fatalf("left behind: %+v %+v", e.f.registry, e.f.sharesec)
	}
	if _, err := os.Stat(spec.Path); err != nil {
		t.Fatal("the folder must be kept")
	}
	wantCode(t, e.call(t, filesapi.OpShareRemovePlan, filesapi.ShareNameParams{Name: "eng"}, nil), filesapi.CodeNotFound)

	n, err := audit.Verify(filepath.Join(e.state, "audit.log"))
	if err != nil || n < 6 {
		t.Fatalf("audit: %d %v", n, err)
	}
}

func TestPlanRefusals(t *testing.T) {
	e := newEnv(t)
	_ = os.Mkdir(filepath.Join(e.root, "data"), 0o750)
	e.f.smbconf = append(e.f.smbconf, confSection("old", filepath.Join(e.root, "data")))
	cases := map[string]func(*filesapi.ShareSpec){
		"name taken in smb.conf": func(s *filesapi.ShareSpec) { s.Name = "LEGACY" },
		"path already shared":    func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = filepath.Join(e.root, "data"), false },
		"folder missing":         func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = filepath.Join(e.root, "nope"), false },
		"folder exists":          func(s *filesapi.ShareSpec) { s.Path = filepath.Join(e.root, "data") },
		"outside the roots":      func(s *filesapi.ShareSpec) { s.Path = "/tmp/x" },
		"unknown SID":            func(s *filesapi.ShareSpec) { s.Access[0].SID = testDom + "-9999" },
		"a user":                 func(s *filesapi.ShareSpec) { s.Access[0].SID = testDom + "-1105" },
		"Domain Admins":          func(s *filesapi.ShareSpec) { s.Access[0].SID = testDom + "-512" },
		"another domain":         func(s *filesapi.ShareSpec) { s.Access[0].SID = "S-1-5-21-1-2-3-4105" },
		"shadow copies":          func(s *filesapi.ShareSpec) { s.ShadowCopies = true },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s := e.spec()
			s.Access = append([]filesapi.Grant(nil), s.Access...)
			mut(&s)
			err := wantCode(t, e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s, Create: true}, nil), filesapi.CodeInvalid)
			if len(err.Details) == 0 {
				t.Fatal("no details")
			}
		})
	}
	// A domain-local group (alias) is fine.
	s := e.spec()
	s.Access[0].SID = testDom + "-4116"
	if err := e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s, Create: true}, &filesapi.Plan{}); err != nil {
		t.Fatal(err)
	}
	// Shares from smb.conf or without the marker are not changed.
	s = e.spec()
	s.Name, s.Path, s.CreateDir = "legacy", "/srv/legacy", false
	wantCode(t, e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s}, nil), filesapi.CodeForbidden)
	wantCode(t, e.call(t, filesapi.OpShareRemovePlan, filesapi.ShareNameParams{Name: "legacy"}, nil), filesapi.CodeForbidden)
	s = e.spec()
	s.CreateDir = false
	wantCode(t, e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s}, nil), filesapi.CodeNotFound)
	// Prerequisites.
	e.f.role = "active directory domain controller"
	wantCode(t, e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: e.spec(), Create: true}, nil), filesapi.CodeUnavailable)
	if err := CheckNotDomainController(context.Background(), e.f); !errors.Is(err, ErrDC) {
		t.Fatalf("DC check: %v", err)
	}
	e.f.role = "member server"
	_ = os.WriteFile(e.a.cfg.State.SmbConf, []byte("[global]\n\tsecurity = ADS\n"), 0o644)
	err := wantCode(t, e.call(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: e.spec(), Create: true}, nil), filesapi.CodeUnavailable)
	if !strings.Contains(strings.Join(err.Details, " "), CheckRegistry) {
		t.Fatalf("details %v", err.Details)
	}
}

func confSection(name, path string) samba.Section {
	return samba.Section{Name: name, Params: [][2]string{{"path", path}}}
}

func TestShadowCopiesAndFailure(t *testing.T) {
	e := newEnv(t)
	e.a.cfg.ShadowCopies = config.ShadowCopies{Snapdir: ".snapshots", Format: "@GMT-%Y.%m.%d-%H.%M.%S", Sort: "desc"}
	s := e.spec()
	s.ShadowCopies, s.RecycleBin, s.AccessBasedEnum, s.Browseable = true, true, true, false
	var pl filesapi.Plan
	e.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s, Create: true}, &pl)
	for _, want := range []string{"browseable = no", "access based share enum = yes", "vfs objects = acl_xattr recycle shadow_copy2",
		"shadow:snapdir = .snapshots", "shadow:format = @GMT-%Y.%m.%d-%H.%M.%S", "shadow:sort = desc", "shadow:localtime = no"} {
		if !strings.Contains(pl.Section, want) {
			t.Fatalf("section lacks %q:\n%s", want, pl.Section)
		}
	}
	// A failing step stops the apply and reports what was done.
	e.f.failOn = "sharesec"
	err := wantCode(t, e.call(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: s, Create: true, Digest: pl.Digest}, nil), filesapi.CodeFailed)
	if len(err.Details) != 3 || !strings.Contains(err.Message, "sharesec") {
		t.Fatalf("failure %+v", err)
	}
	b, _ := os.ReadFile(filepath.Join(e.state, "audit.log"))
	if !strings.Contains(string(b), `"result":"failed"`) {
		t.Fatal("the failure must be audited")
	}
}

func TestDirsGroupsSessions(t *testing.T) {
	e := newEnv(t)
	_ = os.Mkdir(filepath.Join(e.root, "a"), 0o750)
	var dl filesapi.DirList
	e.must(t, filesapi.OpDirsList, filesapi.DirsListParams{Path: e.root}, &dl)
	if len(dl.Entries) != 1 || !dl.Entries[0].Usable || !dl.CanCreate {
		t.Fatalf("dirs %+v", dl)
	}
	wantCode(t, e.call(t, filesapi.OpDirsList, filesapi.DirsListParams{Path: "/etc"}, nil), filesapi.CodeInvalid)
	var gs []filesapi.Group
	e.must(t, filesapi.OpGroupsResolve, filesapi.GroupsResolveParams{SIDs: []string{testDom + "-4105", "S-1-5-18", testDom + "-1"}}, &gs)
	if gs[0].Kind != "group" || gs[1].Name != "SYSTEM" || gs[2].Kind != "unknown" {
		t.Fatalf("groups %+v", gs)
	}
	var ss filesapi.Sessions
	e.must(t, filesapi.OpSessionsList, nil, &ss)
	if ss.Sessions == nil || ss.Files == nil {
		t.Fatal("empty lists must be [] not null")
	}
	var list []filesapi.ShareSummary
	e.must(t, filesapi.OpSharesList, nil, &list)
	if len(list) != 1 || list[0].Name != "legacy" || list[0].Source != "smb.conf" || list[0].Managed {
		t.Fatalf("shares %+v", list)
	}
}

// TestTLS runs the real listener: pinning both ways, enrollment, refusal of
// unknown keys, revocation.
func TestTLS(t *testing.T) {
	e := newEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.a.Serve(ctx, ln) }()
	defer func() {
		cancel()
		<-done
	}()
	addr := ln.Addr().String()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	cid, err := filesapi.LoadOrCreateIdentity(dir, "conductor")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	call := func(id filesapi.Identity, agentPin string, op filesapi.Op, p filesapi.Params, out any) error {
		n++
		req, err := filesapi.NewRequest(fmt.Sprintf("tls-%06d", n), op, actor, p)
		if err != nil {
			return err
		}
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		resp, err := filesapi.Call(cctx, addr, id, agentPin, req)
		if err != nil {
			return err
		}
		return filesapi.DecodeResult(resp, out)
	}
	agentPin := e.a.id.Pin

	// No code outstanding: the handshake fails for an unknown key.
	if err := call(cid, agentPin, filesapi.OpStatus, nil, &filesapi.Status{}); err == nil || filesapi.ErrorCodeOf(err) != "" {
		t.Fatalf("unknown key: %v", err)
	}
	// The client refuses an agent with another key.
	var pm *filesapi.PinMismatchError
	if err := call(cid, "sha256:"+strings.Repeat("Z", 43), filesapi.OpStatus, nil, nil); !errors.As(err, &pm) {
		t.Fatalf("pin mismatch: %v", err)
	}
	token, _, err := e.a.trust.NewCode(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, call(cid, agentPin, filesapi.OpStatus, nil, nil), filesapi.CodeNotEnrolled)
	var er filesapi.EnrollResult
	if err := call(cid, agentPin, filesapi.OpEnroll, filesapi.EnrollParams{Token: token, Name: "dc1"}, &er); err != nil {
		t.Fatal(err)
	}
	if er.AgentPin != agentPin || er.Hostname != "fs1.lab.test" {
		t.Fatalf("enroll %+v", er)
	}
	var st filesapi.Status
	if err := call(cid, agentPin, filesapi.OpStatus, nil, &st); err != nil || !st.Ready() {
		t.Fatalf("status after enrollment: %v %+v", err, st)
	}
	if err := call(cid, agentPin, filesapi.OpUnenroll, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := call(cid, agentPin, filesapi.OpStatus, nil, nil); err == nil || filesapi.ErrorCodeOf(err) != "" {
		t.Fatalf("revoked key: %v", err)
	}
}

func TestTrustCodes(t *testing.T) {
	dir := t.TempDir()
	tr := NewTrust(dir, 3)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tr.now = func() time.Time { return now }
	if err := tr.Enroll("x", "sha256:a", "c", "t"); !errors.Is(err, ErrNoCode) {
		t.Fatalf("no code: %v", err)
	}
	tok, _, _ := tr.NewCode(time.Hour)
	if !tr.Pending() {
		t.Fatal("pending")
	}
	now = now.Add(2 * time.Hour)
	if tr.Pending() || !errors.Is(tr.Enroll(tok, "sha256:a", "c", "t"), ErrExpired) {
		t.Fatal("an expired code must not enroll")
	}
	tok, _, _ = tr.NewCode(time.Hour)
	for i := 0; i < 2; i++ {
		if err := tr.Enroll(tok+"x", "sha256:a", "c", "t"); !errors.Is(err, ErrWrongToken) {
			t.Fatalf("wrong %d: %v", i, err)
		}
	}
	if err := tr.Enroll(tok+"x", "sha256:a", "c", "t"); !errors.Is(err, ErrBurned) {
		t.Fatalf("burn: %v", err)
	}
	if err := tr.Enroll(tok, "sha256:a", "c", "t"); !errors.Is(err, ErrNoCode) {
		t.Fatalf("a burned code must be gone: %v", err)
	}
	tok, _, _ = tr.NewCode(time.Hour)
	if err := tr.Enroll(tok, "sha256:a", "c", "t"); err != nil || !tr.Pinned("sha256:a") || tr.Pending() {
		t.Fatalf("enroll: %v", err)
	}
	st, _ := os.Stat(filepath.Join(dir, "trust.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("trust.json mode %v", st.Mode())
	}
	if ok, err := tr.Remove("sha256:a"); !ok || err != nil || tr.Pinned("sha256:a") {
		t.Fatal("remove")
	}
}

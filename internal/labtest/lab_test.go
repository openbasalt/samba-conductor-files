//go:build lab

// Package labtest holds the integration tests that run on fs1, the lab's
// domain-member file server (scripts/lab-test.sh copies the test binary
// there and runs it as root with the lab's user password in the
// environment). They drive the installed agent over TLS as conductor
// would, and check the result from the SMB side with smbclient.
package labtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/samba-conductor/conductor-files/filesapi"
)

var (
	addr     = envOr("FILES_ADDR", "fs1.lab.conductor.test:7443")
	smbHost  = envOr("FILES_SMB_HOST", "fs1.lab.conductor.test")
	netbios  = envOr("FILES_NETBIOS", "LAB")
	agentBin = envOr("FILES_BIN", "/usr/local/bin/conductor-files")
	actor    = filesapi.Actor{User: "labtest", SID: "S-1-5-21-1-2-3-1000", Session: "labtest-session", IP: "127.0.0.1"}
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

type client struct {
	id  filesapi.Identity
	pin string // the agent's
	n   int
}

func newClient(t *testing.T, pin string) *client {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := filesapi.LoadOrCreateIdentity(dir, "labtest")
	if err != nil {
		t.Fatal(err)
	}
	return &client{id: id, pin: pin}
}

func (c *client) call(op filesapi.Op, params filesapi.Params, out any) error {
	c.n++
	req, err := filesapi.NewRequest(fmt.Sprintf("labtest-%04d", c.n), op, actor, params)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resp, err := filesapi.Call(ctx, addr, c.id, c.pin, req)
	if err != nil {
		return err
	}
	return filesapi.DecodeResult(resp, out)
}

func (c *client) must(t *testing.T, op filesapi.Op, params filesapi.Params, out any) {
	t.Helper()
	if err := c.call(op, params, out); err != nil {
		t.Fatalf("%s: %v", op, err)
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func enrollmentCode(t *testing.T) (string, string) {
	code := strings.TrimSpace(run(t, agentBin, "enroll-code", "--quiet", "--ttl", "10m"))
	token, pin, err := filesapi.ParseEnrollmentCode(code)
	if err != nil {
		t.Fatal(err)
	}
	return token, pin
}

// smb runs smbclient commands on a share as a lab user (password from the
// environment, never on the command line).
func smb(t *testing.T, share, user, cmds string) (string, error) {
	t.Helper()
	cmd := exec.Command("smbclient", "//"+smbHost+"/"+share, "-U", netbios+`\`+user, "-c", cmds)
	cmd.Env = append(os.Environ(), "PASSWD="+os.Getenv("LAB_USER_PASSWORD"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func sidOf(t *testing.T, name string) string {
	return strings.Fields(run(t, "wbinfo", "-n", netbios+`\`+name))[0]
}

func expectCode(t *testing.T, err error, code filesapi.ErrorCode) {
	t.Helper()
	if filesapi.ErrorCodeOf(err) != code {
		t.Fatalf("want error %s, got %v", code, err)
	}
}

func cleanup(t *testing.T) {
	for _, s := range []string{"lt-eng", "lt-manual"} {
		_ = exec.Command("net", "conf", "delshare", s).Run()
	}
	for _, d := range []string{"lt-eng", "lt-link", "lt-open", "lt-manual"} {
		_ = os.RemoveAll("/srv/shares/" + d)
	}
	_ = exec.Command("smbcontrol", "smbd", "reload-config").Run()
}

func TestLabFileServer(t *testing.T) {
	if os.Getenv("LAB_USER_PASSWORD") == "" {
		t.Skip("LAB_USER_PASSWORD not set (run through scripts/lab-test.sh)")
	}
	cleanup(t)
	t.Cleanup(func() { cleanup(t) })
	run(t, agentBin, "enroll-cancel")

	// The agent's key, from a first code (then cancelled).
	_, agentPin := enrollmentCode(t)
	run(t, agentBin, "enroll-cancel")
	c := newClient(t, agentPin)

	t.Run("untrusted key refused at the handshake", func(t *testing.T) {
		err := c.call(filesapi.OpStatus, nil, &filesapi.Status{})
		if err == nil || filesapi.ErrorCodeOf(err) != "" {
			t.Fatalf("an unenrolled key without an outstanding code must fail the TLS handshake, got %v", err)
		}
		t.Logf("refused as expected: %v", err)
	})

	t.Run("wrong agent key refused by the client", func(t *testing.T) {
		other := newClient(t, "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		var pm *filesapi.PinMismatchError
		if err := other.call(filesapi.OpStatus, nil, &filesapi.Status{}); !errors.As(err, &pm) {
			t.Fatalf("want a pin mismatch, got %v", err)
		}
	})

	t.Run("enrollment", func(t *testing.T) {
		token, pin := enrollmentCode(t)
		if pin != agentPin {
			t.Fatalf("the agent key changed: %s vs %s", pin, agentPin)
		}
		// With a code outstanding the handshake passes, but only enroll is served.
		expectCode(t, c.call(filesapi.OpStatus, nil, &filesapi.Status{}), filesapi.CodeNotEnrolled)
		wrong := "A" + token[1:]
		if wrong == token {
			wrong = "B" + token[1:]
		}
		expectCode(t, c.call(filesapi.OpEnroll, filesapi.EnrollParams{Token: wrong, Name: "labtest"}, nil), filesapi.CodeForbidden)
		var res filesapi.EnrollResult
		c.must(t, filesapi.OpEnroll, filesapi.EnrollParams{Token: token, Name: "labtest"}, &res)
		if res.AgentPin != agentPin || res.Hostname == "" {
			t.Fatalf("enroll result %+v", res)
		}
		// Single use.
		expectCode(t, c.call(filesapi.OpEnroll, filesapi.EnrollParams{Token: token, Name: "labtest"}, nil), filesapi.CodeForbidden)
	})

	var st filesapi.Status
	c.must(t, filesapi.OpStatus, nil, &st)
	if !st.Ready() {
		t.Fatalf("not ready: %+v", st.Checks)
	}
	engSID, salesSID := sidOf(t, "Engineering"), sidOf(t, "Sales")

	t.Run("directories", func(t *testing.T) {
		var dl filesapi.DirList
		c.must(t, filesapi.OpDirsList, filesapi.DirsListParams{}, &dl)
		if len(dl.Roots) != 1 || dl.Roots[0] != "/srv/shares" {
			t.Fatalf("roots %v", dl.Roots)
		}
		c.must(t, filesapi.OpDirsList, filesapi.DirsListParams{Path: "/srv/shares"}, &dl)
		if !dl.CanCreate {
			t.Fatal("a new folder must be possible below the root")
		}
		expectCode(t, c.call(filesapi.OpDirsList, filesapi.DirsListParams{Path: "/etc"}, nil), filesapi.CodeInvalid)
	})

	spec := filesapi.ShareSpec{Name: "lt-eng", Path: "/srv/shares/lt-eng", CreateDir: true, Comment: "Lab test",
		Access: []filesapi.Grant{{SID: engSID, Level: filesapi.LevelModify}}, Browseable: true}

	t.Run("refusals", func(t *testing.T) {
		bad := func(mut func(*filesapi.ShareSpec), why string) {
			t.Helper()
			s := spec
			s.Access = append([]filesapi.Grant(nil), spec.Access...)
			mut(&s)
			err := c.call(filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s, Create: true}, &filesapi.Plan{})
			if filesapi.ErrorCodeOf(err) != filesapi.CodeInvalid {
				t.Fatalf("%s: want invalid, got %v", why, err)
			}
			t.Logf("%s: refused: %v", why, err.(*filesapi.Error).Details)
		}
		bad(func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = "/etc/lt-x", true }, "outside the roots")
		bad(func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = "/srv/shares", false }, "a root itself")
		bad(func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = "/srv/shares/../etc", false }, "dot-dot")
		if err := os.Symlink("/etc", "/srv/shares/lt-link"); err != nil {
			t.Fatal(err)
		}
		bad(func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = "/srv/shares/lt-link", false }, "a symbolic link")
		bad(func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = "/srv/shares/lt-link/x", true }, "through a symbolic link")
		if err := os.MkdirAll("/srv/shares/lt-open/sub", 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod("/srv/shares/lt-open", 0o777)
		bad(func(s *filesapi.ShareSpec) { s.Path, s.CreateDir = "/srv/shares/lt-open/sub", false }, "a parent writable by others")
		bad(func(s *filesapi.ShareSpec) { s.Access[0].SID = st.DomainSID + "-99999" }, "an unknown SID")
		bad(func(s *filesapi.ShareSpec) { s.Access[0].SID = sidOf(t, "user0001") }, "a user, not a group")
		bad(func(s *filesapi.ShareSpec) { s.Access[0].SID = st.DomainSID + "-512" }, "Domain Admins")
		bad(func(s *filesapi.ShareSpec) { s.Access[0].SID = "S-1-5-21-1-2-3-4105" }, "another domain")
		bad(func(s *filesapi.ShareSpec) { s.Name = "netlogon" }, "a reserved name")
		bad(func(s *filesapi.ShareSpec) { s.Comment = "100%U" }, "a substitution in the comment")
		bad(func(s *filesapi.ShareSpec) { s.ShadowCopies = true }, "shadow copies without a profile")
	})

	t.Run("create, access, sessions, update, remove", func(t *testing.T) {
		var pl filesapi.Plan
		c.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: spec, Create: true}, &pl)
		t.Logf("plan:\n%s\n%s", pl.Section, strings.Join(pl.Commands, "\n"))
		joined := strings.Join(pl.Commands, "\n")
		for _, want := range []string{"# create the folder /srv/shares/lt-eng", "samba-tool ntacl set --use-s3fs --",
			"net conf import /var/lib/conductor-files/import/lt-eng.conf lt-eng", "sharesec lt-eng --replace=S-1-5-32-544:ALLOWED/0/FULL,",
			engSID + ":ALLOWED/0/CHANGE", "smbcontrol smbd reload-config"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("plan commands lack %q:\n%s", want, joined)
			}
		}
		if _, err := os.Stat("/srv/shares/lt-eng"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("planning must not create the folder")
		}
		other := strings.Repeat("0", 64)
		expectCode(t, c.call(filesapi.OpShareApply, filesapi.SharePlanParams{Spec: spec, Create: true, Digest: other}, nil), filesapi.CodeConflict)
		var ar filesapi.ApplyResult
		c.must(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: spec, Create: true, Digest: pl.Digest}, &ar)

		_ = os.WriteFile("/tmp/lt-upload.txt", []byte("hello from the lab\n"), 0o644)
		if out, err := smb(t, "lt-eng", "user0001", "put /tmp/lt-upload.txt hello.txt; ls"); err != nil || !strings.Contains(out, "hello.txt") {
			t.Fatalf("Engineering member must write: %v\n%s", err, out)
		}
		if out, err := smb(t, "lt-eng", "user0002", "ls"); err == nil || !strings.Contains(out, "NT_STATUS_ACCESS_DENIED") {
			t.Fatalf("Sales member must be refused: %v\n%s", err, out)
		}

		// A live session shows up in sessions.list.
		cmd := exec.Command("smbclient", "//"+smbHost+"/lt-eng", "-U", netbios+`\user0001`)
		cmd.Env = append(os.Environ(), "PASSWD="+os.Getenv("LAB_USER_PASSWORD"))
		stdin, _ := cmd.StdinPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		found := false
		for i := 0; i < 20 && !found; i++ {
			time.Sleep(500 * time.Millisecond)
			var ss filesapi.Sessions
			c.must(t, filesapi.OpSessionsList, nil, &ss)
			for _, tc := range ss.Connections {
				if tc.Share == "lt-eng" {
					for _, s := range ss.Sessions {
						if strings.EqualFold(s.User, netbios+`\user0001`) {
							found = true
						}
					}
				}
			}
		}
		_, _ = io.WriteString(stdin, "quit\n")
		_ = stdin.Close()
		_ = cmd.Wait()
		if !found {
			t.Fatal("the open session is not listed")
		}

		// Update: Engineering read, Sales modify.
		upd := spec
		upd.CreateDir = false
		upd.Access = []filesapi.Grant{{SID: engSID, Level: filesapi.LevelRead}, {SID: salesSID, Level: filesapi.LevelModify}}
		c.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: upd}, &pl)
		if !pl.NTACL.Changed || !pl.ShareACL.Changed || pl.Kind != "update" {
			t.Fatalf("update plan %+v", pl)
		}
		c.must(t, filesapi.OpShareApply, filesapi.SharePlanParams{Spec: upd, Digest: pl.Digest}, &ar)
		if out, err := smb(t, "lt-eng", "user0002", "put /tmp/lt-upload.txt sales.txt; ls"); err != nil || !strings.Contains(out, "sales.txt") {
			t.Fatalf("Sales member must now write: %v\n%s", err, out)
		}
		out, _ := smb(t, "lt-eng", "user0001", "ls; put /tmp/lt-upload.txt eng2.txt")
		if !strings.Contains(out, "hello.txt") || !strings.Contains(out, "NT_STATUS_ACCESS_DENIED") {
			t.Fatalf("Engineering member must read but not write:\n%s", out)
		}

		var d filesapi.ShareDetail
		c.must(t, filesapi.OpShareGet, filesapi.ShareNameParams{Name: "lt-eng"}, &d)
		if !d.Managed || d.Spec == nil || len(d.Spec.Access) != 2 {
			t.Fatalf("share detail %+v", d)
		}
		c.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: upd}, &pl)
		if !pl.NoChange {
			t.Fatalf("re-planning the same spec must be a no-op: %v", pl.Commands)
		}
		// A change made behind the plan's back invalidates its digest.
		run(t, "net", "conf", "setparm", "lt-eng", "comment", "changed by hand")
		upd.Comment = "Lab test, edited"
		c.must(t, filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: upd}, &pl)
		run(t, "net", "conf", "setparm", "lt-eng", "comment", "changed again")
		expectCode(t, c.call(filesapi.OpShareApply, filesapi.SharePlanParams{Spec: upd, Digest: pl.Digest}, nil), filesapi.CodeConflict)

		// Removal keeps the folder.
		var rp filesapi.Plan
		c.must(t, filesapi.OpShareRemovePlan, filesapi.ShareNameParams{Name: "lt-eng"}, &rp)
		c.must(t, filesapi.OpShareRemove, filesapi.ShareNameParams{Name: "lt-eng", Digest: rp.Digest}, &ar)
		if out, err := smb(t, "lt-eng", "user0002", "ls"); err == nil || !strings.Contains(out, "NT_STATUS_BAD_NETWORK_NAME") {
			t.Fatalf("the removed share must be gone: %v\n%s", err, out)
		}
		if _, err := os.Stat("/srv/shares/lt-eng/hello.txt"); err != nil {
			t.Fatalf("the folder and its files must be kept: %v", err)
		}
	})

	t.Run("shares not created by conductor-files are left alone", func(t *testing.T) {
		_ = os.MkdirAll("/srv/shares/lt-manual", 0o750)
		run(t, "net", "conf", "addshare", "lt-manual", "/srv/shares/lt-manual")
		var list []filesapi.ShareSummary
		c.must(t, filesapi.OpSharesList, nil, &list)
		seen := false
		for _, s := range list {
			if s.Name == "lt-manual" {
				seen = true
				if s.Managed || s.Source != "registry" {
					t.Fatalf("lt-manual: %+v", s)
				}
			}
		}
		if !seen {
			t.Fatal("lt-manual not listed")
		}
		s := spec
		s.Name, s.Path, s.CreateDir = "lt-manual", "/srv/shares/lt-manual", false
		expectCode(t, c.call(filesapi.OpSharePlan, filesapi.SharePlanParams{Spec: s}, nil), filesapi.CodeForbidden)
		expectCode(t, c.call(filesapi.OpShareRemovePlan, filesapi.ShareNameParams{Name: "lt-manual"}, nil), filesapi.CodeForbidden)
	})

	t.Run("audit chain and revocation", func(t *testing.T) {
		out := run(t, agentBin, "audit", "verify")
		if !strings.Contains(out, "intact") {
			t.Fatal(out)
		}
		c.must(t, filesapi.OpUnenroll, nil, nil)
		if err := c.call(filesapi.OpStatus, nil, &filesapi.Status{}); err == nil || filesapi.ErrorCodeOf(err) != "" {
			t.Fatalf("a revoked key must fail the handshake, got %v", err)
		}
	})
}

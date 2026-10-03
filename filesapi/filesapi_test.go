package filesapi

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testActor = Actor{User: "lab.admin", SID: "S-1-5-21-1-2-3-1104", Session: "abcdef0123456789", IP: "10.0.0.1"}

func goodSpec() ShareSpec {
	return ShareSpec{Name: "eng", Path: "/srv/shares/eng", Comment: "Engineering", Browseable: true,
		Access: []Grant{{SID: "S-1-5-21-1-2-3-4105", Level: LevelModify}}}
}

func TestShareSpecValidate(t *testing.T) {
	if err := goodSpec().Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ShareSpec){
		"reserved name":     func(s *ShareSpec) { s.Name = "SYSVOL" },
		"bad name":          func(s *ShareSpec) { s.Name = "-x" },
		"name too long":     func(s *ShareSpec) { s.Name = strings.Repeat("a", 64) },
		"relative path":     func(s *ShareSpec) { s.Path = "srv/x" },
		"unclean path":      func(s *ShareSpec) { s.Path = "/srv/shares/../etc" },
		"trailing slash":    func(s *ShareSpec) { s.Path = "/srv/shares/x/" },
		"percent in path":   func(s *ShareSpec) { s.Path = "/srv/shares/%U" },
		"backslash in path": func(s *ShareSpec) { s.Path = `/srv/shares/a\b` },
		"newline in path":   func(s *ShareSpec) { s.Path = "/srv/shares/a\nb" },
		"leading dash":      func(s *ShareSpec) { s.Path = "/srv/shares/-rf" },
		"spaces around":     func(s *ShareSpec) { s.Path = "/srv/shares/ a" },
		"comment percent":   func(s *ShareSpec) { s.Comment = "%S" },
		"comment newline":   func(s *ShareSpec) { s.Comment = "a\n[global]" },
		"comment quote":     func(s *ShareSpec) { s.Comment = `a"b` },
		"no access":         func(s *ShareSpec) { s.Access = nil },
		"builtin sid":       func(s *ShareSpec) { s.Access[0].SID = "S-1-5-32-544" },
		"bad level":         func(s *ShareSpec) { s.Access[0].Level = "owner" },
		"duplicate sid":     func(s *ShareSpec) { s.Access = append(s.Access, s.Access[0]) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			s := goodSpec()
			s.Access = append([]Grant(nil), s.Access...)
			mut(&s)
			var ve *ValidationError
			if err := s.Validate(); !errors.As(err, &ve) {
				t.Fatalf("want a validation error, got %v", err)
			}
		})
	}
	s := goodSpec()
	s.Name = "data$"
	s.Path = "/srv/shares/Área Comum"
	if err := s.Validate(); err != nil {
		t.Fatalf("a hidden share and a UTF-8 folder name are fine: %v", err)
	}
}

func TestNormalized(t *testing.T) {
	s := goodSpec()
	s.Access = []Grant{{SID: "S-1-5-21-1-2-3-9", Level: LevelRead, Name: "B"}, {SID: "S-1-5-21-1-2-3-10", Level: LevelFull, Name: "A"}}
	n := s.Normalized()
	if n.Access[0].SID != "S-1-5-21-1-2-3-10" || n.Access[0].Name != "" || s.Access[0].Name != "B" {
		t.Fatalf("normalized %+v (original %+v)", n.Access, s.Access)
	}
}

func TestRequestDecode(t *testing.T) {
	req, err := NewRequest("req-0000000001", OpSharePlan, testActor, SharePlanParams{Spec: goodSpec(), Create: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := req.Decode()
	if err != nil || p.(*SharePlanParams).Spec.Name != "eng" {
		t.Fatalf("decode: %v %+v", err, p)
	}
	bad := []func(*Request){
		func(r *Request) { r.Version = 2 },
		func(r *Request) { r.ID = "x" },
		func(r *Request) { r.Op = "exec" },
		func(r *Request) { r.Actor.User = "" },
		func(r *Request) { r.Actor.SID = "nobody" },
		func(r *Request) { r.Params = json.RawMessage(`{"spec":{},"create":true,"extra":1}`) },
		func(r *Request) { r.Params = json.RawMessage(`{"spec":{"name":"x"}}{}`) },
	}
	for i, mut := range bad {
		r := req
		mut(&r)
		if _, err := r.Decode(); err == nil {
			t.Fatalf("case %d: decoded", i)
		}
	}
	// Validation problems come back as "invalid" with details.
	s := goodSpec()
	s.Path = "relative"
	_, err = NewRequest("req-0000000002", OpSharePlan, testActor, SharePlanParams{Spec: s, Create: true})
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeInvalid || len(e.Details) == 0 {
		t.Fatalf("want invalid with details, got %v", err)
	}
	// A folder is created only with a new share.
	s = goodSpec()
	s.CreateDir = true
	if _, err := NewRequest("req-0000000003", OpSharePlan, testActor, SharePlanParams{Spec: s}); ErrorCodeOf(err) != CodeInvalid {
		t.Fatalf("create_dir on an update: %v", err)
	}
	if _, err := NewRequest("req-0000000004", OpShareRemove, testActor, ShareNameParams{Name: "eng", Digest: "xyz"}); err == nil {
		t.Fatal("bad digest accepted")
	}
}

func TestMutating(t *testing.T) {
	for op := range Allowlist {
		want := op == OpEnroll || op == OpUnenroll || op == OpShareApply || op == OpShareRemove
		if op.Mutating() != want {
			t.Errorf("%s: mutating=%v", op, op.Mutating())
		}
	}
}

func TestEnrollmentCode(t *testing.T) {
	tok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	pin := "sha256:" + strings.Repeat("A", 43)
	code := FormatEnrollmentCode(tok, pin)
	gotTok, gotPin, err := ParseEnrollmentCode("  " + code + "\n")
	if err != nil || gotTok != tok || gotPin != pin {
		t.Fatalf("round trip: %v %q %q", err, gotTok, gotPin)
	}
	for _, bad := range []string{"", "cfe1." + tok, "cfe2." + tok + "." + strings.Repeat("A", 43), "cfe1.short." + strings.Repeat("A", 43),
		"cfe1." + tok + ".bad"} {
		if _, _, err := ParseEnrollmentCode(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	if TokenHash(tok) == TokenHash(tok+"x") || TokenHash(tok) == tok {
		t.Fatal("token hash")
	}
}

func TestNormalizeAddress(t *testing.T) {
	ok := map[string]string{
		"fs1.lab.conductor.test":      "fs1.lab.conductor.test:7443",
		"fs1.lab.conductor.test:9000": "fs1.lab.conductor.test:9000",
		"10.93.0.20":                  "10.93.0.20:7443",
		"[2001:db8::1]:7443":          "[2001:db8::1]:7443",
		"2001:db8::1":                 "[2001:db8::1]:7443",
	}
	for in, want := range ok {
		if got, err := NormalizeAddress(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "fs1:0", "fs1:99999", "fs1 two", "fs1/x", "https://fs1", "-fs1"} {
		if got, err := NormalizeAddress(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, got)
		}
	}
}

func TestIdentity(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateIdentity(dir, "x"); err == nil {
		t.Fatal("a world-readable key directory must be refused")
	}
	_ = os.Chmod(dir, 0o700)
	id, err := LoadOrCreateIdentity(dir, "conductor")
	if err != nil || !ValidPin(id.Pin) {
		t.Fatalf("identity: %v %q", err, id.Pin)
	}
	again, err := LoadOrCreateIdentity(dir, "conductor")
	if err != nil || again.Pin != id.Pin {
		t.Fatal("the key must be reused")
	}
	st, _ := os.Stat(filepath.Join(dir, KeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	_ = os.Chmod(filepath.Join(dir, KeyFile), 0o644)
	if _, err := LoadIdentity(filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile)); err == nil {
		t.Fatal("a readable key file must be refused")
	}
}

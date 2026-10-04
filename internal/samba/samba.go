// Package samba runs the Samba programs conductor-files is allowed to use,
// with fixed absolute paths, argument lists built from validated values, no
// shell and a minimal environment, and parses what they print.
package samba

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Paths of the programs (configuration [samba]).
type Paths struct {
	Net        string `toml:"net"`
	Sharesec   string `toml:"sharesec"`
	SambaTool  string `toml:"samba_tool"`
	Smbstatus  string `toml:"smbstatus"`
	Smbcontrol string `toml:"smbcontrol"`
	Wbinfo     string `toml:"wbinfo"`
	Testparm   string `toml:"testparm"`
}

// DefaultPaths are the Debian and Ubuntu locations.
func DefaultPaths() Paths {
	return Paths{Net: "/usr/bin/net", Sharesec: "/usr/bin/sharesec", SambaTool: "/usr/bin/samba-tool",
		Smbstatus: "/usr/bin/smbstatus", Smbcontrol: "/usr/bin/smbcontrol", Wbinfo: "/usr/bin/wbinfo", Testparm: "/usr/bin/testparm"}
}

// Runner runs a program and returns its standard output. Tests replace it.
type Runner interface {
	Run(ctx context.Context, prog string, args ...string) ([]byte, error)
}

// ExecRunner runs programs for real.
type ExecRunner struct {
	// Timeout per program (default 60 s).
	Timeout time.Duration
}

// maxOutput bounds what a program may print.
const maxOutput = 16 << 20

// CommandError is a program that failed.
type CommandError struct {
	Prog   string
	Args   []string
	Code   int
	Stderr string
}

func (e *CommandError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if len(msg) > 600 {
		msg = msg[:600] + "..."
	}
	return fmt.Sprintf("%s exited with status %d: %s", e.Prog, e.Code, msg)
}

type limitedBuffer struct {
	bytes.Buffer
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxOutput {
		b.over = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// Run implements Runner.
func (r ExecRunner) Run(ctx context.Context, prog string, args ...string) ([]byte, error) {
	t := r.Timeout
	if t <= 0 {
		t = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	cmd := exec.CommandContext(ctx, prog, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "HOME=/root"}
	cmd.Dir = "/"
	var out, errOut limitedBuffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if out.over {
		return nil, fmt.Errorf("%s printed more than %d bytes", prog, maxOutput)
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out.Bytes(), &CommandError{Prog: prog, Args: args, Code: ee.ExitCode(), Stderr: errOut.String()}
		}
		return nil, err
	}
	return out.Bytes(), nil
}

// Tools are the Samba programs with their runner.
type Tools struct {
	P Paths
	R Runner
}

// Missing lists the configured tools that are not executable regular
// files: a package is missing (on Fedora samba-tool is in samba-tools).
func (t Tools) Missing() []string {
	var out []string
	for _, p := range []string{t.P.Net, t.P.Sharesec, t.P.SambaTool, t.P.Smbstatus, t.P.Smbcontrol, t.P.Wbinfo, t.P.Testparm} {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			out = append(out, p)
		}
	}
	return out
}

// ---- configuration (testparm, net conf) ----

// Section is one share (or [global]) of a configuration.
type Section struct {
	Name   string
	Params [][2]string
}

// Get returns a parameter's value (keys compared case-insensitively,
// spaces normalised).
func (s Section) Get(key string) (string, bool) {
	k := NormKey(key)
	for _, p := range s.Params {
		if NormKey(p[0]) == k {
			return p[1], true
		}
	}
	return "", false
}

// NormKey normalises a parameter name: lower case, single spaces.
func NormKey(k string) string { return strings.Join(strings.Fields(strings.ToLower(k)), " ") }

var sectionRE = regexp.MustCompile(`^\s*\[([^\]]*)\]\s*$`)

// ParseConf reads smb.conf-format text (net conf list, testparm -s). Lines
// before the first section, comments and lines without "=" are skipped.
func ParseConf(out string) []Section {
	var list []Section
	cur := -1
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if m := sectionRE.FindStringSubmatch(line); m != nil {
			list = append(list, Section{Name: strings.TrimSpace(m[1])})
			cur = len(list) - 1
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		if !ok || cur < 0 {
			continue
		}
		list[cur].Params = append(list[cur].Params, [2]string{strings.TrimSpace(k), strings.TrimSpace(v)})
	}
	return list
}

// RenderSection renders one section the way net conf prints it.
func RenderSection(s Section) string {
	var b strings.Builder
	b.WriteString("[" + s.Name + "]\n")
	for _, p := range s.Params {
		b.WriteString("\t" + p[0] + " = " + p[1] + "\n")
	}
	return b.String()
}

// Registry lists the shares (and [global], if any) in the registry.
func (t Tools) Registry(ctx context.Context) ([]Section, error) {
	out, err := t.R.Run(ctx, t.P.Net, "conf", "list")
	if err != nil {
		return nil, err
	}
	return ParseConf(string(out)), nil
}

// Effective lists the effective configuration (smb.conf with includes and
// the registry), [global] first when present.
func (t Tools) Effective(ctx context.Context) ([]Section, error) {
	out, err := t.R.Run(ctx, t.P.Testparm, "-s")
	if err != nil {
		// testparm exits non-zero on warnings with the dump still printed.
		if len(out) == 0 {
			return nil, err
		}
	}
	return ParseConf(string(out)), nil
}

// Parameter returns one effective global parameter.
func (t Tools) Parameter(ctx context.Context, name string) (string, error) {
	out, err := t.R.Run(ctx, t.P.Testparm, "-s", "--parameter-name="+name)
	if err != nil && len(out) == 0 {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Version returns the Samba version ("4.22.11-Debian-...").
func (t Tools) Version(ctx context.Context) (string, error) {
	out, err := t.R.Run(ctx, t.P.Testparm, "-V")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "Version ")), nil
}

// ImportArgs is the argv of `net conf import FILE SHARE` (replaces that one
// section of the registry configuration in a transaction).
func (t Tools) ImportArgs(file, share string) []string {
	return []string{t.P.Net, "conf", "import", file, share}
}

// DelShareArgs is the argv of `net conf delshare SHARE`.
func (t Tools) DelShareArgs(share string) []string {
	return []string{t.P.Net, "conf", "delshare", share}
}

// ShareSecView returns the share ACL in SDDL (`sharesec SHARE --viewsddl`).
func (t Tools) ShareSecView(ctx context.Context, share string) (string, error) {
	out, err := t.R.Run(ctx, t.P.Sharesec, share, "--viewsddl")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ShareSecReplaceArgs is the argv that replaces a share ACL.
func (t Tools) ShareSecReplaceArgs(share, acl string) []string {
	return []string{t.P.Sharesec, share, "--replace=" + acl}
}

// ShareSecDeleteArgs is the argv that deletes a share's security descriptor.
func (t Tools) ShareSecDeleteArgs(share string) []string {
	return []string{t.P.Sharesec, share, "--delete"}
}

// NTACLGet returns a directory's NT ACL in SDDL, as smbd's VFS sees it.
func (t Tools) NTACLGet(ctx context.Context, path string) (string, error) {
	out, err := t.R.Run(ctx, t.P.SambaTool, "ntacl", "get", "--as-sddl", "--use-s3fs", "--", path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// NTACLSetArgs is the argv that writes a directory's NT ACL through smbd's
// VFS (security.NTACL and the matching POSIX ACLs).
func (t Tools) NTACLSetArgs(sddl, path string) []string {
	return []string{t.P.SambaTool, "ntacl", "set", "--use-s3fs", "--", sddl, path}
}

// ReloadArgs is the argv that makes smbd re-read its configuration.
func (t Tools) ReloadArgs() []string { return []string{t.P.Smbcontrol, "smbd", "reload-config"} }

// RunArgs runs an argv built by one of the *Args functions.
func (t Tools) RunArgs(ctx context.Context, argv []string) error {
	_, err := t.R.Run(ctx, argv[0], argv[1:]...)
	return err
}

// ---- winbind ----

// SID kinds as wbinfo reports them (enum lsa_SidType).
const (
	SidUser     = 1
	SidGroup    = 2 // domain group
	SidDomain   = 3
	SidAlias    = 4 // domain-local or builtin group
	SidWellKnwn = 5
)

// LookupSID resolves a SID ("LAB\Engineering", 2).
func (t Tools) LookupSID(ctx context.Context, sid string) (string, int, error) {
	out, err := t.R.Run(ctx, t.P.Wbinfo, "-s", sid)
	if err != nil {
		return "", 0, err
	}
	return ParseLookup(string(out))
}

// ParseLookup reads `wbinfo -s` output: "DOMAIN\name TYPE".
func ParseLookup(out string) (string, int, error) {
	line := strings.TrimSpace(out)
	i := strings.LastIndexByte(line, ' ')
	if i < 0 {
		return "", 0, fmt.Errorf("wbinfo: unexpected %q", line)
	}
	kind, err := strconv.Atoi(line[i+1:])
	if err != nil {
		return "", 0, fmt.Errorf("wbinfo: unexpected %q", line)
	}
	return line[:i], kind, nil
}

// DomainInfo is the joined domain.
type DomainInfo struct{ NetBIOS, Realm, SID string }

// Domain returns the domain this server is a member of.
func (t Tools) Domain(ctx context.Context) (DomainInfo, error) {
	own, err := t.R.Run(ctx, t.P.Wbinfo, "--own-domain")
	if err != nil {
		return DomainInfo{}, err
	}
	name := strings.TrimSpace(string(own))
	out, err := t.R.Run(ctx, t.P.Wbinfo, "-D", name)
	if err != nil {
		return DomainInfo{}, err
	}
	d := DomainInfo{NetBIOS: name}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Alt_Name":
			d.Realm = strings.TrimSpace(v)
		case "SID":
			d.SID = strings.TrimSpace(v)
		}
	}
	if d.SID == "" {
		return d, errors.New("wbinfo: no domain SID")
	}
	return d, nil
}

// TrustOK checks the machine account's trust (`wbinfo -t`).
func (t Tools) TrustOK(ctx context.Context) error {
	_, err := t.R.Run(ctx, t.P.Wbinfo, "-t")
	return err
}

// ---- sessions ----

// StatusJSON returns `smbstatus --json`.
func (t Tools) StatusJSON(ctx context.Context) ([]byte, error) {
	return t.R.Run(ctx, t.P.Smbstatus, "--json")
}

package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/samba-conductor/conductor-files/filesapi"
	"github.com/samba-conductor/conductor-files/internal/fsguard"
	"github.com/samba-conductor/conductor-files/internal/samba"
	"github.com/samba-conductor/conductor-files/internal/sddl"
)

// Check names (also the i18n keys in conductor).
const (
	CheckNotDC     = "member_not_dc"
	CheckSecurity  = "security_ads"
	CheckTrust     = "domain_trust"
	CheckRegistry  = "registry_shares"
	CheckACLXattr  = "acl_xattr"
	CheckRoots     = "roots"
	CheckSmbstatus = "smbstatus_json"
)

// managedKey marks the registry shares conductor-files owns.
const managedKey = "conductor-files:managed"

// ErrDC is returned by CheckNotDomainController on a domain controller.
var ErrDC = errors.New("this server is an Active Directory domain controller: conductor-files runs only on domain-member file servers")

// CheckNotDomainController refuses a DC (serve does not start there).
func CheckNotDomainController(ctx context.Context, sb Samba) error {
	role, err := sb.Parameter(ctx, "server role")
	if err != nil {
		return fmt.Errorf("reading the server role: %w", err)
	}
	if strings.Contains(strings.ToLower(role), "domain controller") {
		return ErrDC
	}
	return nil
}

// Status checks the prerequisites and describes the server.
func (a *Agent) Status(ctx context.Context) filesapi.Status {
	st := filesapi.Status{Hostname: a.cfg.Server.Name, Version: a.version, Roots: slices.Clone(a.cfg.Shares.Roots),
		ShadowCopies: a.cfg.ShadowCopies.Enabled(), Time: a.now().UTC()}
	add := func(name string, err error, detail string) {
		c := filesapi.Check{Name: name, OK: err == nil, Detail: detail}
		if err != nil {
			c.Detail = err.Error()
		}
		st.Checks = append(st.Checks, c)
	}
	if v, err := a.sb.Version(ctx); err == nil {
		st.SambaVersion = v
	}
	role, err := a.sb.Parameter(ctx, "server role")
	switch {
	case err != nil:
		add(CheckNotDC, err, "")
	case strings.Contains(strings.ToLower(role), "domain controller"):
		add(CheckNotDC, ErrDC, "")
	case !strings.Contains(strings.ToLower(role), "member"):
		add(CheckNotDC, fmt.Errorf("server role is %q, not a member server", role), "")
	default:
		add(CheckNotDC, nil, role)
	}
	sec, err := a.sb.Parameter(ctx, "security")
	if err == nil && !strings.EqualFold(sec, "ADS") {
		err = fmt.Errorf("security = %s (ADS required)", sec)
	}
	add(CheckSecurity, err, sec)
	if d, err := a.sb.Domain(ctx); err == nil {
		st.Domain, st.Realm, st.DomainSID = d.NetBIOS, d.Realm, d.SID
	}
	add(CheckTrust, a.sb.TrustOK(ctx), st.Realm)
	add(CheckRegistry, a.registryIncluded(), "")
	vfs, err := a.sb.Parameter(ctx, "vfs objects")
	if err == nil && !slices.Contains(strings.Fields(vfs), "acl_xattr") {
		err = fmt.Errorf("vfs objects = %q (acl_xattr required in [global])", vfs)
	}
	add(CheckACLXattr, err, vfs)
	var rootErrs []error
	for _, r := range a.cfg.Shares.Roots {
		if err := a.guard.CheckRoot(r); err != nil {
			rootErrs = append(rootErrs, err)
		}
	}
	add(CheckRoots, errors.Join(rootErrs...), strings.Join(a.cfg.Shares.Roots, ", "))
	_, err = a.sb.StatusJSON(ctx)
	add(CheckSmbstatus, err, "")
	return st
}

// registryIncluded checks that [global] of the main configuration reads
// shares from the registry.
func (a *Agent) registryIncluded() error {
	b, err := a.readSmbConf()
	if err != nil {
		return err
	}
	for _, sec := range samba.ParseConf(string(b)) {
		if !strings.EqualFold(sec.Name, "global") {
			continue
		}
		for _, p := range sec.Params {
			k, v := samba.NormKey(p[0]), strings.ToLower(strings.TrimSpace(p[1]))
			switch {
			case k == "include" && v == "registry", k == "config backend" && v == "registry",
				k == "registry shares" && (v == "yes" || v == "true" || v == "1"):
				return nil
			}
		}
	}
	return fmt.Errorf("%s: [global] needs \"include = registry\" (shares from the registry configuration)", a.cfg.State.SmbConf)
}

// ready refuses changes while a prerequisite fails.
func (a *Agent) ready(ctx context.Context) (filesapi.Status, *filesapi.Error) {
	st := a.Status(ctx)
	var bad []string
	for _, c := range st.Checks {
		if !c.OK && c.Name != CheckSmbstatus {
			bad = append(bad, c.Name+": "+c.Detail)
		}
	}
	if len(bad) > 0 {
		return st, &filesapi.Error{Code: filesapi.CodeUnavailable, Message: "the file server does not meet the prerequisites", Details: bad}
	}
	if st.DomainSID == "" {
		return st, &filesapi.Error{Code: filesapi.CodeUnavailable, Message: "the domain SID is unknown (winbind)"}
	}
	return st, nil
}

func failed(err error) *filesapi.Error {
	return &filesapi.Error{Code: filesapi.CodeFailed, Message: err.Error()}
}

func invalid(problems ...string) *filesapi.Error {
	return &filesapi.Error{Code: filesapi.CodeInvalid, Message: "the request is not valid", Details: problems}
}

// ---- shares ----

// shareView joins the effective configuration and the registry.
type shareView struct {
	effective []samba.Section
	registry  []samba.Section
}

func (a *Agent) shares(ctx context.Context) (shareView, error) {
	eff, err := a.sb.Effective(ctx)
	if err != nil {
		return shareView{}, err
	}
	reg, err := a.sb.Registry(ctx)
	if err != nil {
		return shareView{}, err
	}
	return shareView{effective: eff, registry: reg}, nil
}

func findSection(list []samba.Section, name string) (samba.Section, bool) {
	for _, s := range list {
		if strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return samba.Section{}, false
}

// isShare excludes [global] (and [homes]/[printers], which are not
// directories).
func isShare(name string) bool {
	switch strings.ToLower(name) {
	case "global", "homes", "printers":
		return false
	}
	return true
}

func yes(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1", "on":
		return true
	case "no", "false", "0", "off":
		return false
	}
	return def
}

func (v shareView) summary(name string) (filesapi.ShareSummary, bool) {
	eff, inEff := findSection(v.effective, name)
	reg, inReg := findSection(v.registry, name)
	if !inEff && !inReg {
		return filesapi.ShareSummary{}, false
	}
	sec := eff
	if inReg {
		sec = reg
	}
	s := filesapi.ShareSummary{Name: sec.Name, Source: "smb.conf"}
	if inReg {
		s.Source = "registry"
		m, _ := reg.Get(managedKey)
		s.Managed = yes(m, false)
	}
	s.Path, _ = sec.Get("path")
	s.Comment, _ = sec.Get("comment")
	b, ok := sec.Get("browseable")
	if !ok {
		b, ok = sec.Get("browsable")
	}
	s.Browseable = !ok || yes(b, true)
	return s, true
}

// paths maps share paths to share names.
func (v shareView) paths() map[string]string {
	out := map[string]string{}
	for _, list := range [][]samba.Section{v.effective, v.registry} {
		for _, s := range list {
			if !isShare(s.Name) {
				continue
			}
			if p, ok := s.Get("path"); ok && p != "" {
				if _, seen := out[p]; !seen {
					out[p] = s.Name
				}
			}
		}
	}
	return out
}

func (a *Agent) sharesList(ctx context.Context) (any, *filesapi.Error) {
	v, err := a.shares(ctx)
	if err != nil {
		return nil, failed(err)
	}
	var names []string
	seen := map[string]bool{}
	for _, list := range [][]samba.Section{v.registry, v.effective} {
		for _, s := range list {
			k := strings.ToLower(s.Name)
			if isShare(s.Name) && !seen[k] && k != "ipc$" && k != "print$" {
				seen[k] = true
				names = append(names, s.Name)
			}
		}
	}
	out := []filesapi.ShareSummary{}
	for _, n := range names {
		if s, ok := v.summary(n); ok {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(x, y filesapi.ShareSummary) int {
		return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
	})
	return out, nil
}

func (a *Agent) shareGet(ctx context.Context, name string) (any, *filesapi.Error) {
	v, err := a.shares(ctx)
	if err != nil {
		return nil, failed(err)
	}
	sum, ok := v.summary(name)
	if !ok || !isShare(name) {
		return nil, &filesapi.Error{Code: filesapi.CodeNotFound, Message: "no share named " + name}
	}
	d := filesapi.ShareDetail{ShareSummary: sum}
	if reg, ok := findSection(v.registry, name); ok {
		d.Params = reg.Params
	} else if eff, ok := findSection(v.effective, name); ok {
		d.Params = eff.Params
	}
	dom, _ := a.sb.Domain(ctx)
	names := a.namer(ctx)
	shareSD, shareErr := a.sb.ShareSecView(ctx, sum.Name)
	if shareErr == nil {
		if sd, err := sddl.Parse(shareSD, dom.SID); err == nil {
			d.ShareACL = aces(sd.DACL, names, sddl.ShareRights)
		}
	}
	if sum.Path != "" {
		if nt, err := a.sb.NTACLGet(ctx, sum.Path); err != nil {
			d.NTACLError = err.Error()
		} else if sd, err := sddl.Parse(nt, dom.SID); err != nil {
			d.NTACLError = err.Error()
		} else {
			d.NTACL = aces(sd.DACL, names, sddl.FileRights)
		}
	}
	if sum.Managed && shareErr == nil {
		spec := a.specOf(ctx, v, sum, shareSD, dom.SID)
		d.Spec = &spec
	}
	return d, nil
}

// specOf reconstructs a managed share's spec: options from its section,
// access from its share ACL (the fixed administrator entries left out).
func (a *Agent) specOf(ctx context.Context, v shareView, sum filesapi.ShareSummary, shareSD, domSID string) filesapi.ShareSpec {
	sec, _ := findSection(v.registry, sum.Name)
	spec := filesapi.ShareSpec{Name: sum.Name, Path: sum.Path, Comment: sum.Comment, Browseable: sum.Browseable}
	abe, _ := sec.Get("access based share enum")
	spec.AccessBasedEnum = yes(abe, false)
	vfs, _ := sec.Get("vfs objects")
	spec.RecycleBin = slices.Contains(strings.Fields(vfs), "recycle")
	spec.ShadowCopies = slices.Contains(strings.Fields(vfs), "shadow_copy2")
	if sd, err := sddl.Parse(shareSD, domSID); err == nil {
		fixed := fixedShareSIDs(domSID)
		for _, e := range sd.DACL {
			if e.Type != "A" || slices.Contains(fixed, e.SID) || !filesapi.ValidDomainSID(e.SID) {
				continue
			}
			lvl := ""
			switch e.Mask {
			case sddl.ShareRead:
				lvl = filesapi.LevelRead
			case sddl.ShareChange:
				lvl = filesapi.LevelModify
			case sddl.ShareFull:
				lvl = filesapi.LevelFull
			}
			if lvl != "" {
				spec.Access = append(spec.Access, filesapi.Grant{SID: e.SID, Level: lvl})
			}
		}
	}
	names := a.namer(ctx)
	for i := range spec.Access {
		spec.Access[i].Name = names(spec.Access[i].SID)
	}
	return spec
}

// ---- names ----

var wellKnownNames = map[string]string{
	"S-1-1-0": "Everyone", "S-1-3-0": "CREATOR OWNER", "S-1-3-1": "CREATOR GROUP", "S-1-5-11": "Authenticated Users",
	"S-1-5-18": "SYSTEM", "S-1-5-32-544": "BUILTIN\\Administrators", "S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests", "S-1-5-32-551": "BUILTIN\\Backup Operators",
}

// namer returns a SID→name function with a per-request cache.
func (a *Agent) namer(ctx context.Context) func(string) string {
	cache := map[string]string{}
	return func(sid string) string {
		if n, ok := wellKnownNames[sid]; ok {
			return n
		}
		if n, ok := cache[sid]; ok {
			return n
		}
		n, _, err := a.sb.LookupSID(ctx, sid)
		if err != nil {
			n = ""
		}
		cache[sid] = n
		return n
	}
}

func aces(list []sddl.ACE, names func(string) string, rights func(uint32) string) []filesapi.ACE {
	out := make([]filesapi.ACE, 0, len(list))
	for _, e := range list {
		out = append(out, filesapi.ACE{Type: sddl.TypeName(e.Type), SID: e.SID, Name: names(e.SID), Mask: e.Mask, Flags: e.Flags, Rights: rights(e.Mask)})
	}
	return out
}

// ---- directories, groups, sessions ----

func (a *Agent) dirsList(ctx context.Context, p *filesapi.DirsListParams) (any, *filesapi.Error) {
	v, err := a.shares(ctx)
	if err != nil {
		return nil, failed(err)
	}
	list, err := a.guard.List(p.Path, v.paths())
	if err != nil {
		switch {
		case errors.Is(err, fsguard.ErrOutside):
			return nil, invalid(err.Error())
		case errors.Is(err, fsguard.ErrNotFound), errors.Is(err, fsguard.ErrSymlink):
			return nil, &filesapi.Error{Code: filesapi.CodeNotFound, Message: err.Error()}
		}
		return nil, failed(err)
	}
	return list, nil
}

func kindName(k int) string {
	switch k {
	case samba.SidUser:
		return "user"
	case samba.SidGroup:
		return "group"
	case samba.SidAlias:
		return "alias"
	case samba.SidWellKnwn:
		return "well-known"
	}
	return "unknown"
}

func (a *Agent) groupsResolve(ctx context.Context, p *filesapi.GroupsResolveParams) (any, *filesapi.Error) {
	out := make([]filesapi.Group, 0, len(p.SIDs))
	for _, s := range p.SIDs {
		g := filesapi.Group{SID: s, Kind: "unknown"}
		if n, ok := wellKnownNames[s]; ok {
			g.Name, g.Kind = n, "well-known"
		} else if n, k, err := a.sb.LookupSID(ctx, s); err == nil {
			g.Name, g.Kind = n, kindName(k)
		}
		out = append(out, g)
	}
	return out, nil
}

func (a *Agent) sessions(ctx context.Context) (any, *filesapi.Error) {
	raw, err := a.sb.StatusJSON(ctx)
	if err != nil {
		return nil, failed(err)
	}
	s, t, f, err := samba.ParseStatusJSON(raw)
	if err != nil {
		return nil, failed(err)
	}
	if s == nil {
		s = []filesapi.Session{}
	}
	if t == nil {
		t = []filesapi.TreeConnect{}
	}
	if f == nil {
		f = []filesapi.OpenFile{}
	}
	return filesapi.Sessions{Time: a.now().UTC(), Sessions: s, Connections: t, Files: f}, nil
}

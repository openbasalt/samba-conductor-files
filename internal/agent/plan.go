package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/openbasalt/samba-conductor-files/filesapi"
	"github.com/openbasalt/samba-conductor-files/internal/audit"
	"github.com/openbasalt/samba-conductor-files/internal/fsguard"
	"github.com/openbasalt/samba-conductor-files/internal/samba"
	"github.com/openbasalt/samba-conductor-files/internal/sddl"
)

// Fixed principals of every managed share: SYSTEM, BUILTIN\Administrators
// and the domain's Domain Admins have full control (NT ACL); the last two
// also on the share ACL. Owner and group of the directory:
// BUILTIN\Administrators.
const (
	sidSystem = "S-1-5-18"
	sidAdmins = "S-1-5-32-544"
)

func domainAdmins(domSID string) string { return domSID + "-512" }

func fixedShareSIDs(domSID string) []string { return []string{sidAdmins, domainAdmins(domSID)} }

// step is one action of a plan; display is exactly what is shown.
type step struct {
	display string
	// One of: a directory to create, a program (argv), optionally with a
	// section written to importFile first.
	mkdir      string
	argv       []string
	importFile string
	section    string
	// verifyNT re-reads the NT ACL after writing it.
	verifyNT *sddl.SD
	ntPath   string
}

type planned struct {
	plan  filesapi.Plan
	steps []step
}

var plainArg = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// shellQuote renders argv the way a shell user would type it.
func shellQuote(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if plainArg.MatchString(a) {
			out[i] = a
		} else {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// desiredSection renders the registry configuration of a managed share.
func (a *Agent) desiredSection(spec filesapi.ShareSpec, globalVFS string) samba.Section {
	p := [][2]string{{"path", spec.Path}}
	if spec.Comment != "" {
		p = append(p, [2]string{"comment", spec.Comment})
	}
	p = append(p, [2]string{"read only", "no"}, [2]string{"guest ok", "no"}, [2]string{"browseable", yesNo(spec.Browseable)})
	if spec.AccessBasedEnum {
		p = append(p, [2]string{"access based share enum", "yes"})
	}
	if spec.RecycleBin || spec.ShadowCopies {
		vfs := strings.Fields(globalVFS)
		if spec.RecycleBin && !slices.Contains(vfs, "recycle") {
			vfs = append(vfs, "recycle")
		}
		if spec.ShadowCopies && !slices.Contains(vfs, "shadow_copy2") {
			vfs = append(vfs, "shadow_copy2")
		}
		p = append(p, [2]string{"vfs objects", strings.Join(vfs, " ")})
	}
	if spec.RecycleBin {
		p = append(p, [2]string{"recycle:repository", ".recycle/%U"}, [2]string{"recycle:keeptree", "yes"},
			[2]string{"recycle:versions", "yes"}, [2]string{"recycle:touch", "yes"})
	}
	if spec.ShadowCopies {
		sc := a.cfg.ShadowCopies
		p = append(p, [2]string{"shadow:snapdir", sc.Snapdir}, [2]string{"shadow:format", sc.Format})
		if sc.Sort != "" {
			p = append(p, [2]string{"shadow:sort", sc.Sort})
		}
		p = append(p, [2]string{"shadow:localtime", yesNo(sc.Localtime)})
	}
	p = append(p, [2]string{managedKey, "yes"})
	return samba.Section{Name: spec.Name, Params: p}
}

// sameSection compares two sections' parameters (names normalised, order
// ignored).
func sameSection(x, y samba.Section) bool {
	norm := func(s samba.Section) []string {
		out := make([]string, len(s.Params))
		for i, p := range s.Params {
			out[i] = samba.NormKey(p[0]) + "=" + strings.TrimSpace(p[1])
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(norm(x), norm(y))
}

var shareLevel = map[string]string{filesapi.LevelRead: "READ", filesapi.LevelModify: "CHANGE", filesapi.LevelFull: "FULL"}
var shareMask = map[string]uint32{filesapi.LevelRead: sddl.ShareRead, filesapi.LevelModify: sddl.ShareChange, filesapi.LevelFull: sddl.ShareFull}
var fileMask = map[string]uint32{filesapi.LevelRead: sddl.FileReadEx, filesapi.LevelModify: sddl.FileModify, filesapi.LevelFull: sddl.FileAll}

// desiredShareACL returns the share ACL entries and the sharesec argument.
func desiredShareACL(spec filesapi.ShareSpec, domSID string) ([]sddl.ACE, string) {
	list := []sddl.ACE{{Type: "A", Mask: sddl.ShareFull, SID: sidAdmins}, {Type: "A", Mask: sddl.ShareFull, SID: domainAdmins(domSID)}}
	arg := []string{sidAdmins + ":ALLOWED/0/FULL", domainAdmins(domSID) + ":ALLOWED/0/FULL"}
	for _, g := range spec.Access {
		list = append(list, sddl.ACE{Type: "A", Mask: shareMask[g.Level], SID: g.SID})
		arg = append(arg, g.SID+":ALLOWED/0/"+shareLevel[g.Level])
	}
	return list, strings.Join(arg, ",")
}

// desiredNTACL returns the share directory's security descriptor.
func desiredNTACL(spec filesapi.ShareSpec, domSID string) sddl.SD {
	sd := sddl.SD{Owner: sidAdmins, Group: sidAdmins, Protected: true, AutoInherited: true, HasDACL: true}
	for _, s := range []string{sidSystem, sidAdmins, domainAdmins(domSID)} {
		sd.DACL = append(sd.DACL, sddl.ACE{Type: "A", Flags: "OICI", Mask: sddl.FileAll, SID: s})
	}
	for _, g := range spec.Access {
		sd.DACL = append(sd.DACL, sddl.ACE{Type: "A", Flags: "OICI", Mask: fileMask[g.Level], SID: g.SID})
	}
	return sd
}

func digestOf(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func guardProblem(err error) *filesapi.Error {
	switch {
	case errors.Is(err, fsguard.ErrOutside), errors.Is(err, fsguard.ErrSymlink), errors.Is(err, fsguard.ErrNotFound),
		errors.Is(err, fsguard.ErrExists), errors.Is(err, fsguard.ErrUnsafe):
		return invalid("path: " + err.Error())
	}
	var ve *filesapi.ValidationError
	if errors.As(err, &ve) {
		return invalid(ve.Problems...)
	}
	if err.Error() != "" && strings.HasPrefix(err.Error(), "the path") {
		return invalid("path: " + err.Error())
	}
	return failed(err)
}

// planShare computes the exact change that makes the server match spec.
func (a *Agent) planShare(ctx context.Context, spec filesapi.ShareSpec, create bool) (planned, *filesapi.Error) {
	var out planned
	if err := spec.Validate(); err != nil {
		var ve *filesapi.ValidationError
		if errors.As(err, &ve) {
			return out, invalid(ve.Problems...)
		}
		return out, invalid(err.Error())
	}
	spec = spec.Normalized()
	st, apiErr := a.ready(ctx)
	if apiErr != nil {
		return out, apiErr
	}
	dom := st.DomainSID
	v, err := a.shares(ctx)
	if err != nil {
		return out, failed(err)
	}
	cur, exists := v.summary(spec.Name)
	switch {
	case create && exists:
		return out, invalid(fmt.Sprintf("name: a share named %q already exists", cur.Name))
	case !create && !exists:
		return out, &filesapi.Error{Code: filesapi.CodeNotFound, Message: "no share named " + spec.Name}
	case !create && !cur.Managed:
		return out, &filesapi.Error{Code: filesapi.CodeForbidden, Message: "share " + cur.Name + " is not managed by conductor-files (only shares it created are changed)"}
	}
	if !create {
		spec.Name = cur.Name // keep the stored spelling
	}
	var problems []string
	var warnings []filesapi.Warning
	for p, name := range v.paths() {
		if strings.EqualFold(name, spec.Name) {
			continue
		}
		switch {
		case p == spec.Path:
			problems = append(problems, fmt.Sprintf("path: %s is already shared as %q", p, name))
		case strings.HasPrefix(spec.Path, p+"/"):
			warnings = append(warnings, filesapi.Warning{Code: filesapi.WarnInsideShare, Arg: name})
		case strings.HasPrefix(p, spec.Path+"/"):
			warnings = append(warnings, filesapi.Warning{Code: filesapi.WarnContainsShare, Arg: name})
		}
	}
	if spec.CreateDir {
		if err := a.guard.CheckCreate(spec.Path); err != nil {
			e := guardProblem(err)
			if e.Code != filesapi.CodeInvalid {
				return out, e
			}
			problems = append(problems, e.Details...)
		}
	} else if err := a.guard.CheckDir(spec.Path); err != nil {
		e := guardProblem(err)
		if e.Code != filesapi.CodeInvalid {
			return out, e
		}
		problems = append(problems, e.Details...)
	}
	names := a.namer(ctx)
	for _, g := range spec.Access {
		switch {
		case !strings.HasPrefix(g.SID, dom+"-"):
			problems = append(problems, fmt.Sprintf("access: %s is not a group of the domain %s", g.SID, st.Domain))
			continue
		case g.SID == domainAdmins(dom):
			problems = append(problems, "access: Domain Admins always have full control; do not list them")
			continue
		}
		n, kind, err := a.sb.LookupSID(ctx, g.SID)
		if err != nil {
			problems = append(problems, fmt.Sprintf("access: %s is unknown to the domain (winbind)", g.SID))
			continue
		}
		if kind != samba.SidGroup && kind != samba.SidAlias {
			problems = append(problems, fmt.Sprintf("access: %s (%s) is not a group", n, g.SID))
		}
	}
	if spec.ShadowCopies && !a.cfg.ShadowCopies.Enabled() {
		problems = append(problems, "shadow copies: this file server has no [shadow_copies] profile")
	}
	if len(problems) > 0 {
		return out, invalid(problems...)
	}

	globalVFS, err := a.sb.Parameter(ctx, "vfs objects")
	if err != nil {
		return out, failed(err)
	}
	section := a.desiredSection(spec, globalVFS)
	regSec, inReg := findSection(v.registry, spec.Name)
	sectionBefore := ""
	if inReg {
		sectionBefore = samba.RenderSection(regSec)
	}
	sectionChanged := !inReg || !sameSection(regSec, section)

	// Share ACL.
	shareBefore := ""
	var shareBeforeACEs []sddl.ACE
	if exists {
		if s, err := a.sb.ShareSecView(ctx, cur.Name); err == nil {
			shareBefore = s
			if sd, err := sddl.Parse(s, dom); err == nil {
				shareBeforeACEs = sd.DACL
			}
		}
	}
	shareAfter, shareArg := desiredShareACL(spec, dom)
	shareChanged := !exists || !sddl.EqualACL(shareBeforeACEs, shareAfter)

	// NT ACL of the directory.
	ntBefore := ""
	var ntBeforeSD sddl.SD
	if !spec.CreateDir {
		s, err := a.sb.NTACLGet(ctx, spec.Path)
		if err != nil {
			return out, failed(fmt.Errorf("reading the NT ACL of %s: %w", spec.Path, err))
		}
		ntBefore = s
		if ntBeforeSD, err = sddl.Parse(s, dom); err != nil {
			return out, failed(err)
		}
	}
	ntAfter := desiredNTACL(spec, dom)
	ntChanged := spec.CreateDir || !sddl.Equal(ntBeforeSD, ntAfter)

	kind := "update"
	if create {
		kind = "create"
	}
	pl := filesapi.Plan{Kind: kind, Name: spec.Name, Path: spec.Path, CreateDir: spec.CreateDir, SectionBefore: sectionBefore,
		Section: samba.RenderSection(section), Warnings: warnings,
		ShareACL: filesapi.ACLChange{Before: aces(shareBeforeACEs, names, sddl.ShareRights), After: aces(shareAfter, names, sddl.ShareRights), Changed: shareChanged},
		NTACL: filesapi.ACLChange{Before: aces(ntBeforeSD.DACL, names, sddl.FileRights), After: aces(ntAfter.DACL, names, sddl.FileRights),
			Changed: ntChanged, SDDL: ntAfter.String()}}
	if !create && cur.Path != spec.Path {
		pl.Warnings = append(pl.Warnings, filesapi.Warning{Code: filesapi.WarnMoved, Arg: cur.Path})
	}
	if !create && ntChanged {
		pl.Warnings = append(pl.Warnings, filesapi.Warning{Code: filesapi.WarnExistingContent})
	}

	var steps []step
	if spec.CreateDir {
		steps = append(steps, step{display: fmt.Sprintf("# create the folder %s (owner root:root, mode 0700, no symbolic links followed)", spec.Path), mkdir: spec.Path})
	}
	// Order: the directory's NT ACL first (so a new share never exposes a
	// directory with other permissions), then the share, then its ACL.
	if ntChanged {
		argv := a.sb.NTACLSetArgs(ntAfter.String(), spec.Path)
		want := ntAfter
		steps = append(steps, step{display: shellQuote(argv), argv: argv, verifyNT: &want, ntPath: spec.Path})
	}
	if sectionChanged {
		file := filepath.Join(a.importDir(), spec.Name+".conf")
		argv := a.sb.ImportArgs(file, spec.Name)
		steps = append(steps, step{display: shellQuote(argv), argv: argv, importFile: file, section: samba.RenderSection(section)})
	}
	if shareChanged {
		argv := a.sb.ShareSecReplaceArgs(spec.Name, shareArg)
		steps = append(steps, step{display: shellQuote(argv), argv: argv})
	}
	if len(steps) > 0 {
		argv := a.sb.ReloadArgs()
		steps = append(steps, step{display: shellQuote(argv), argv: argv})
	}
	for _, s := range steps {
		pl.Commands = append(pl.Commands, s.display)
	}
	pl.NoChange = len(steps) == 0
	pl.Digest = digestOf(struct {
		V        int
		Kind     string
		Spec     filesapi.ShareSpec
		Section  string
		Share    string
		NT       string
		Commands []string
	}{1, kind, spec, sectionBefore, shareBefore, ntBefore, pl.Commands})
	return planned{plan: pl, steps: steps}, nil
}

// planRemove computes the removal of a managed share (its folder is kept).
func (a *Agent) planRemove(ctx context.Context, name string) (planned, *filesapi.Error) {
	var out planned
	st, apiErr := a.ready(ctx)
	if apiErr != nil {
		return out, apiErr
	}
	v, err := a.shares(ctx)
	if err != nil {
		return out, failed(err)
	}
	cur, exists := v.summary(name)
	switch {
	case !exists || !isShare(name):
		return out, &filesapi.Error{Code: filesapi.CodeNotFound, Message: "no share named " + name}
	case !cur.Managed:
		return out, &filesapi.Error{Code: filesapi.CodeForbidden, Message: "share " + cur.Name + " is not managed by conductor-files"}
	}
	regSec, _ := findSection(v.registry, cur.Name)
	shareBefore, _ := a.sb.ShareSecView(ctx, cur.Name)
	var before []sddl.ACE
	if sd, err := sddl.Parse(shareBefore, st.DomainSID); err == nil {
		before = sd.DACL
	}
	names := a.namer(ctx)
	pl := filesapi.Plan{Kind: "remove", Name: cur.Name, Path: cur.Path, SectionBefore: samba.RenderSection(regSec),
		ShareACL: filesapi.ACLChange{Before: aces(before, names, sddl.ShareRights), After: []filesapi.ACE{}, Changed: true},
		Warnings: []filesapi.Warning{{Code: filesapi.WarnFolderKept, Arg: cur.Path}}}
	steps := []step{}
	// sharesec needs the share to exist, so its descriptor goes first (a
	// stale descriptor would otherwise apply to a future share of the same
	// name); the directory's NT ACL still restricts access meanwhile.
	for _, argv := range [][]string{a.sb.ShareSecDeleteArgs(cur.Name), a.sb.DelShareArgs(cur.Name), a.sb.ReloadArgs()} {
		steps = append(steps, step{display: shellQuote(argv), argv: argv})
		pl.Commands = append(pl.Commands, shellQuote(argv))
	}
	pl.Digest = digestOf(struct {
		V        int
		Kind     string
		Name     string
		Section  string
		Share    string
		Commands []string
	}{1, "remove", cur.Name, pl.SectionBefore, shareBefore, pl.Commands})
	return planned{plan: pl, steps: steps}, nil
}

// execute runs the steps in order and returns the ones that completed.
func (a *Agent) execute(ctx context.Context, steps []step) ([]string, error) {
	var done []string
	for _, s := range steps {
		if err := a.runStep(ctx, s); err != nil {
			return done, fmt.Errorf("%s: %w", s.display, err)
		}
		done = append(done, s.display)
	}
	return done, nil
}

func (a *Agent) runStep(ctx context.Context, s step) error {
	switch {
	case s.mkdir != "":
		return a.guard.Create(s.mkdir)
	case s.importFile != "":
		if err := os.MkdirAll(filepath.Dir(s.importFile), 0o700); err != nil {
			return err
		}
		_ = os.Remove(s.importFile)
		f, err := os.OpenFile(s.importFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(s.section); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		defer func() { _ = os.Remove(s.importFile) }()
		return a.sb.RunArgs(ctx, s.argv)
	}
	if err := a.sb.RunArgs(ctx, s.argv); err != nil {
		return err
	}
	if s.verifyNT != nil {
		got, err := a.sb.NTACLGet(ctx, s.ntPath)
		if err != nil {
			return fmt.Errorf("reading the NT ACL back: %w", err)
		}
		dom := ""
		if d, err := a.sb.Domain(ctx); err == nil {
			dom = d.SID
		}
		sd, err := sddl.Parse(got, dom)
		if err != nil {
			return err
		}
		if !sddl.Equal(sd, *s.verifyNT) {
			return fmt.Errorf("the NT ACL read back (%s) differs from the one written", got)
		}
	}
	return nil
}

func (a *Agent) applyShare(ctx context.Context, req filesapi.Request, pin string, p *filesapi.SharePlanParams) (any, *filesapi.Error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	target := p.Spec.Name
	if p.Digest == "" {
		return nil, invalid("digest: the apply needs the digest of the reviewed plan")
	}
	pl, apiErr := a.planShare(ctx, p.Spec, p.Create)
	if apiErr != nil {
		a.record(req, pin, target, audit.ResultFailed, apiErr.Message+" "+strings.Join(apiErr.Details, "; "), p.Digest, nil)
		return nil, apiErr
	}
	return a.applyPlanned(ctx, req, pin, target, p.Digest, pl)
}

func (a *Agent) applyRemove(ctx context.Context, req filesapi.Request, pin string, p *filesapi.ShareNameParams) (any, *filesapi.Error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if p.Digest == "" {
		return nil, invalid("digest: the removal needs the digest of the reviewed plan")
	}
	pl, apiErr := a.planRemove(ctx, p.Name)
	if apiErr != nil {
		a.record(req, pin, p.Name, audit.ResultFailed, apiErr.Message, p.Digest, nil)
		return nil, apiErr
	}
	return a.applyPlanned(ctx, req, pin, p.Name, p.Digest, pl)
}

func (a *Agent) applyPlanned(ctx context.Context, req filesapi.Request, pin, target, digest string, pl planned) (any, *filesapi.Error) {
	if pl.plan.Digest != digest {
		a.record(req, pin, target, audit.ResultDenied, "the share changed since the plan was reviewed", digest, nil)
		return nil, &filesapi.Error{Code: filesapi.CodeConflict, Message: "the share or its folder changed since the plan was reviewed; plan again"}
	}
	done, err := a.execute(ctx, pl.steps)
	if err != nil {
		a.record(req, pin, target, audit.ResultFailed, err.Error(), digest, done)
		return nil, &filesapi.Error{Code: filesapi.CodeFailed, Message: err.Error(), Details: done}
	}
	a.record(req, pin, target, audit.ResultOK, pl.plan.Kind+" "+pl.plan.Path, digest, done)
	return filesapi.ApplyResult{Digest: digest, Steps: done}, nil
}

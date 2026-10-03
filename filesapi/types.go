package filesapi

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ValidationError lists every problem of a request (shown to the user).
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return "invalid: " + strings.Join(e.Problems, "; ") }

// Access levels of a group on a share.
const (
	LevelRead   = "read"
	LevelModify = "modify"
	LevelFull   = "full"
)

// Levels lists the access levels, weakest first.
var Levels = []string{LevelRead, LevelModify, LevelFull}

// Limits.
const (
	MaxGrants     = 32
	MaxPathLen    = 1024
	MaxCommentLen = 256
	MaxSIDs       = 256
)

var (
	shareNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\$?$`)
	// domainSIDRE is an account SID of an AD domain (S-1-5-21-a-b-c-rid).
	domainSIDRE = regexp.MustCompile(`^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}$`)
	tokenRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// reservedShares are names a managed share may never take.
var reservedShares = []string{"global", "homes", "printers", "print$", "ipc$", "netlogon", "sysvol"}

// ValidShareName reports whether name may be a managed share.
func ValidShareName(name string) bool {
	return shareNameRE.MatchString(name) && !slices.Contains(reservedShares, strings.ToLower(name))
}

// ValidDomainSID reports whether s looks like an AD domain account SID.
func ValidDomainSID(s string) bool { return domainSIDRE.MatchString(s) }

// safeText reports whether v may be written into a Samba configuration
// value: valid UTF-8, no control characters, no '%' (Samba expands
// substitutions such as %U in values), no backslash (a line continuation)
// and no double quote.
func safeText(v string) bool {
	if !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) || r == '%' || r == '\\' || r == '"' || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// ValidSharePath checks the shape of a share path (the agent also checks
// it is below a configured root and free of symbolic links): absolute,
// clean, at most MaxPathLen bytes, and every component safe text without
// leading or trailing spaces.
func ValidSharePath(p string) error {
	switch {
	case p == "" || !strings.HasPrefix(p, "/"):
		return errors.New("the path must be absolute")
	case len(p) > MaxPathLen:
		return fmt.Errorf("the path is longer than %d bytes", MaxPathLen)
	case path.Clean(p) != p || p == "/":
		return errors.New("the path must be clean (no '.', '..', '//' or trailing '/')")
	}
	for _, c := range strings.Split(p[1:], "/") {
		if len(c) > 255 || !safeText(c) || strings.TrimSpace(c) != c || strings.HasPrefix(c, "-") {
			return fmt.Errorf("the path component %q is not allowed (no control characters, %%, \\, \", leading '-' or surrounding spaces)", c)
		}
	}
	return nil
}

// ValidComment checks a share comment.
func ValidComment(c string) error {
	if len(c) > MaxCommentLen || !safeText(c) || strings.TrimSpace(c) != c {
		return fmt.Errorf("the comment must be at most %d bytes without control characters, %%, \\ or \" and without surrounding spaces", MaxCommentLen)
	}
	return nil
}

// Grant gives one AD group (by SID) an access level on a share.
type Grant struct {
	SID   string `json:"sid"`
	Level string `json:"level"`
	// Name is informational (shown in previews); the agent ignores it and
	// resolves the SID itself.
	Name string `json:"name,omitempty"`
}

// ShareSpec is the desired state of a managed share.
type ShareSpec struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// CreateDir creates the last path component (its parent must exist).
	CreateDir bool    `json:"create_dir,omitempty"`
	Comment   string  `json:"comment,omitempty"`
	Access    []Grant `json:"access"`
	// Browseable lists the share in browse lists.
	Browseable bool `json:"browseable"`
	// AccessBasedEnum hides the share and entries from users without access.
	AccessBasedEnum bool `json:"access_based_enum,omitempty"`
	// RecycleBin keeps deleted files in .recycle/<user> (vfs_recycle).
	RecycleBin bool `json:"recycle_bin,omitempty"`
	// ShadowCopies exposes snapshots as "Previous Versions"
	// (vfs_shadow_copy2 with the host's [shadow_copies] profile).
	ShadowCopies bool `json:"shadow_copies,omitempty"`
}

// Validate implements the checks that need no server state.
func (s ShareSpec) Validate() error {
	var p []string
	if !ValidShareName(s.Name) {
		p = append(p, "share name: letters, digits, '.', '_', '-' (up to 63, optional trailing '$'), not a reserved name")
	}
	if err := ValidSharePath(s.Path); err != nil {
		p = append(p, "path: "+err.Error())
	}
	if err := ValidComment(s.Comment); err != nil {
		p = append(p, "comment: "+err.Error())
	}
	switch {
	case len(s.Access) == 0:
		p = append(p, "access: at least one group is required")
	case len(s.Access) > MaxGrants:
		p = append(p, fmt.Sprintf("access: at most %d groups", MaxGrants))
	}
	seen := map[string]bool{}
	for _, g := range s.Access {
		if !ValidDomainSID(g.SID) {
			p = append(p, fmt.Sprintf("access: %q is not a domain group SID", g.SID))
		}
		if !slices.Contains(Levels, g.Level) {
			p = append(p, fmt.Sprintf("access: level %q (read, modify or full)", g.Level))
		}
		if seen[g.SID] {
			p = append(p, fmt.Sprintf("access: %s is listed twice", g.SID))
		}
		seen[g.SID] = true
		if len(g.Name) > 300 {
			p = append(p, "access: name too long")
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Normalized returns the spec with the grants sorted by SID and the
// informational names dropped (the form plans and digests are made from).
func (s ShareSpec) Normalized() ShareSpec {
	out := s
	out.Access = make([]Grant, len(s.Access))
	for i, g := range s.Access {
		out.Access[i] = Grant{SID: g.SID, Level: g.Level}
	}
	slices.SortFunc(out.Access, func(a, b Grant) int { return strings.Compare(a.SID, b.SID) })
	return out
}

// ---- parameters ----

// EnrollParams pins the caller's key with a one-time token.
type EnrollParams struct {
	Token string `json:"token"`
	// Name labels the pin on the agent (conductor's host name).
	Name string `json:"name"`
}

// Validate implements Params.
func (p EnrollParams) Validate() error {
	if !tokenRE.MatchString(p.Token) {
		return errors.New("token: malformed")
	}
	if p.Name == "" || len(p.Name) > 253 || !safeText(p.Name) {
		return errors.New("name: 1-253 printable characters")
	}
	return nil
}

// DirsListParams lists the subdirectories of a root or of a directory
// below one ("" lists the roots).
type DirsListParams struct {
	Path string `json:"path,omitempty"`
}

// Validate implements Params.
func (p DirsListParams) Validate() error {
	if p.Path == "" {
		return nil
	}
	if err := ValidSharePath(p.Path); err != nil {
		return &ValidationError{Problems: []string{"path: " + err.Error()}}
	}
	return nil
}

// GroupsResolveParams asks the agent (winbind) for names of SIDs.
type GroupsResolveParams struct {
	SIDs []string `json:"sids"`
}

// Validate implements Params.
func (p GroupsResolveParams) Validate() error {
	if len(p.SIDs) == 0 || len(p.SIDs) > MaxSIDs {
		return fmt.Errorf("sids: 1-%d", MaxSIDs)
	}
	for _, s := range p.SIDs {
		if !sidRE.MatchString(s) {
			return fmt.Errorf("sids: %q is not a SID", s)
		}
	}
	return nil
}

// ShareNameParams names one share. Digest is set when applying a removal
// (the digest of the reviewed plan).
type ShareNameParams struct {
	Name   string `json:"name"`
	Digest string `json:"digest,omitempty"`
}

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate implements Params.
func (p ShareNameParams) Validate() error {
	if !shareNameRE.MatchString(p.Name) {
		return errors.New("name: not a share name")
	}
	if p.Digest != "" && !digestRE.MatchString(p.Digest) {
		return errors.New("digest: 64 hex digits")
	}
	return nil
}

// SharePlanParams plans (share.plan) or applies (share.apply) a share spec.
// Create says whether the share must be new (true) or an existing managed
// share (false). Apply requires the digest of the reviewed plan.
type SharePlanParams struct {
	Spec   ShareSpec `json:"spec"`
	Create bool      `json:"create"`
	Digest string    `json:"digest,omitempty"`
}

// Validate implements Params.
func (p SharePlanParams) Validate() error {
	if p.Digest != "" && !digestRE.MatchString(p.Digest) {
		return errors.New("digest: 64 hex digits")
	}
	if p.Spec.CreateDir && !p.Create {
		return &ValidationError{Problems: []string{"a folder is created only with a new share"}}
	}
	return p.Spec.Validate()
}

// ---- results ----

// EnrollResult answers a successful enrollment.
type EnrollResult struct {
	Hostname string `json:"hostname"`
	// AgentPin is the agent's own key pin (as in the enrollment code).
	AgentPin string `json:"agent_pin"`
	Version  string `json:"version"`
}

// Check is one prerequisite of a file server.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Status describes a file server.
type Status struct {
	Hostname     string    `json:"hostname"`
	Version      string    `json:"version"`
	SambaVersion string    `json:"samba_version"`
	Domain       string    `json:"domain"` // NetBIOS name
	Realm        string    `json:"realm"`
	DomainSID    string    `json:"domain_sid"`
	Roots        []string  `json:"roots"`
	Checks       []Check   `json:"checks"`
	ShadowCopies bool      `json:"shadow_copies"`
	Time         time.Time `json:"time"`
}

// Ready reports whether every prerequisite passed.
func (s Status) Ready() bool {
	for _, c := range s.Checks {
		if !c.OK {
			return false
		}
	}
	return true
}

// DirEntry is a subdirectory.
type DirEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	// Share is the share whose path this is ("" if none).
	Share string `json:"share,omitempty"`
	// Usable: may hold a share (a real directory, not inside another share).
	Usable bool `json:"usable"`
	// Reason why it is not usable.
	Reason string `json:"reason,omitempty"`
}

// DirList is the content of a root or of a directory below one.
type DirList struct {
	Path      string     `json:"path"`
	Root      string     `json:"root"`
	Parent    string     `json:"parent,omitempty"` // "" at a root
	Roots     []string   `json:"roots"`
	Entries   []DirEntry `json:"entries"`
	Truncated bool       `json:"truncated,omitempty"`
	// CanCreate: a new folder may be created here (root-owned, not
	// writable by group or others).
	CanCreate bool `json:"can_create"`
}

// Group is a resolved SID.
type Group struct {
	SID  string `json:"sid"`
	Name string `json:"name,omitempty"` // DOMAIN\name
	// Kind: "group", "alias", "user", "well-known", "unknown".
	Kind string `json:"kind"`
}

// ShareSummary is one share in a list.
type ShareSummary struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Comment string `json:"comment,omitempty"`
	// Source: "registry" or "smb.conf".
	Source string `json:"source"`
	// Managed: created by conductor-files (only those are edited).
	Managed    bool `json:"managed"`
	Browseable bool `json:"browseable"`
}

// ACE is one access control entry, resolved for display.
type ACE struct {
	Type  string `json:"type"` // "allow", "deny" or the raw SDDL type
	SID   string `json:"sid"`
	Name  string `json:"name,omitempty"`
	Mask  uint32 `json:"mask"`
	Flags string `json:"flags,omitempty"` // SDDL inheritance flags, e.g. "OICI"
	// Rights in words: read, modify, full (NT ACL) or READ, CHANGE, FULL
	// (share ACL); a hex mask otherwise.
	Rights string `json:"rights"`
}

// String renders the ACE on one line.
func (a ACE) String() string {
	who := a.SID
	if a.Name != "" {
		who = a.Name + " (" + a.SID + ")"
	}
	s := strings.ToUpper(a.Type) + " " + who + " " + a.Rights
	if a.Flags != "" {
		s += " [" + a.Flags + "]"
	}
	return s
}

// ShareDetail is one share with its permissions.
type ShareDetail struct {
	ShareSummary
	// Params are the share's parameters as Samba reports them, in order.
	Params [][2]string `json:"params"`
	// ShareACL from sharesec; NTACL of the share's directory.
	ShareACL []ACE `json:"share_acl"`
	NTACL    []ACE `json:"nt_acl"`
	// NTACLError explains a missing NT ACL (directory gone, not readable).
	NTACLError string `json:"nt_acl_error,omitempty"`
	// Spec is the share as a spec (managed shares only), for editing.
	Spec *ShareSpec `json:"spec,omitempty"`
}

// ACLChange is the before/after of one ACL.
type ACLChange struct {
	Before  []ACE  `json:"before"`
	After   []ACE  `json:"after"`
	Changed bool   `json:"changed"`
	SDDL    string `json:"sddl,omitempty"` // the descriptor that is written
}

// Plan is the exact change for a share spec or a removal.
type Plan struct {
	Kind string `json:"kind"` // "create", "update" or "remove"
	Name string `json:"name"`
	Path string `json:"path"`
	// CreateDir: the directory is created (root:root, 0700) first.
	CreateDir bool `json:"create_dir,omitempty"`
	// SectionBefore and Section are the registry configuration of the
	// share before and after ("" when absent).
	SectionBefore string    `json:"section_before,omitempty"`
	Section       string    `json:"section,omitempty"`
	ShareACL      ACLChange `json:"share_acl"`
	NTACL         ACLChange `json:"nt_acl"`
	// Commands are the exact programs and arguments run, in order.
	Commands []string  `json:"commands"`
	Warnings []Warning `json:"warnings,omitempty"`
	// NoChange: nothing would be written.
	NoChange bool `json:"no_change,omitempty"`
	// Digest binds the apply to this plan (spec + current state).
	Digest string `json:"digest"`
}

// Warning codes of a plan (conductor translates them; Arg is a share name
// or a path).
const (
	WarnInsideShare     = "inside_share"     // the folder is inside another share's folder
	WarnContainsShare   = "contains_share"   // the folder contains another share's folder
	WarnMoved           = "moved"            // the share points to another folder; the old one is kept
	WarnExistingContent = "existing_content" // existing content keeps its own permissions
	WarnFolderKept      = "folder_kept"      // a removed share's folder and files are kept
)

// Warning is something the administrator should know before applying.
type Warning struct {
	Code string `json:"code"`
	Arg  string `json:"arg,omitempty"`
}

// ApplyResult tells what an apply did.
type ApplyResult struct {
	Digest string   `json:"digest"`
	Steps  []string `json:"steps"`
}

// Session is an SMB session.
type Session struct {
	SessionID  string `json:"session_id"`
	PID        string `json:"pid"`
	User       string `json:"user"`
	Group      string `json:"group,omitempty"`
	Machine    string `json:"machine"`
	Remote     string `json:"remote,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Encryption string `json:"encryption,omitempty"`
	Signing    string `json:"signing,omitempty"`
}

// TreeConnect is a session's connection to a share.
type TreeConnect struct {
	Share      string `json:"share"`
	PID        string `json:"pid"`
	Machine    string `json:"machine"`
	Since      string `json:"since,omitempty"`
	Encryption string `json:"encryption,omitempty"`
	Signing    string `json:"signing,omitempty"`
}

// OpenFile is a file held open by a client.
type OpenFile struct {
	PID    string `json:"pid"`
	User   string `json:"user,omitempty"`
	Path   string `json:"path"`
	Access string `json:"access,omitempty"`
	Oplock string `json:"oplock,omitempty"`
	Locked bool   `json:"locked,omitempty"`
}

// Sessions is the live state of the SMB server.
type Sessions struct {
	Time        time.Time     `json:"time"`
	Sessions    []Session     `json:"sessions"`
	Connections []TreeConnect `json:"connections"`
	Files       []OpenFile    `json:"files"`
}

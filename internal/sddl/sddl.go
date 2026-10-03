// Package sddl parses and renders the subset of the Security Descriptor
// Definition Language that Samba prints for file and share security
// descriptors (`samba-tool ntacl get --as-sddl`, `sharesec --viewsddl`), and
// builds the descriptors conductor-files writes.
//
// Parsing resolves SID aliases (BA, DA, ...) to full SIDs with the joined
// domain's SID, and access rights to masks, so two descriptors that differ
// only in how Samba spelled them compare equal.
package sddl

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ACE is one access control entry.
type ACE struct {
	// Type is the SDDL ACE type: "A" (allow), "D" (deny), or another.
	Type string
	// Flags are the inheritance flags in canonical order (OI CI NP IO ID).
	Flags string
	Mask  uint32
	SID   string
}

// SD is a security descriptor (the SACL is not modelled).
type SD struct {
	Owner, Group string
	// Protected: the DACL does not inherit from the parent (SDDL "P").
	Protected bool
	// AutoInherited: SDDL "AI".
	AutoInherited bool
	DACL          []ACE
	// HasDACL: a "D:" part was present.
	HasDACL bool
}

// Access masks.
const (
	FileAll     uint32 = 0x001f01ff // FA: full control
	FileModify  uint32 = 0x001301bf // modify (read, write, execute, delete)
	FileReadEx  uint32 = 0x001200a9 // read & execute (list folder, traverse)
	FileRead    uint32 = 0x00120089 // FR
	FileWrite   uint32 = 0x00120116 // FW
	FileExecute uint32 = 0x001200a0 // FX
	ShareFull   uint32 = 0x001f01ff
	ShareChange uint32 = 0x001301ff
	ShareRead   uint32 = 0x001200a9
)

var rightTokens = map[string]uint32{
	"GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
	"RC": 0x00020000, "SD": 0x00010000, "WD": 0x00040000, "WO": 0x00080000,
	"RP": 0x10, "WP": 0x20, "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "LO": 0x80, "DT": 0x40, "CR": 0x100,
	"FA": FileAll, "FR": FileRead, "FW": FileWrite, "FX": FileExecute,
	"KA": 0x000f003f, "KR": 0x00020019, "KW": 0x00020006, "KX": 0x00020019,
}

// Well-known SID aliases.
var wellKnown = map[string]string{
	"WD": "S-1-1-0", "CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4",
	"NU": "S-1-5-2", "IU": "S-1-5-4", "SU": "S-1-5-6", "AN": "S-1-5-7", "ED": "S-1-5-9", "PS": "S-1-5-10",
	"AU": "S-1-5-11", "RC": "S-1-5-12", "SY": "S-1-5-18", "LS": "S-1-5-19", "NS": "S-1-5-20",
	"BA": "S-1-5-32-544", "BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "PU": "S-1-5-32-547",
	"AO": "S-1-5-32-548", "SO": "S-1-5-32-549", "PO": "S-1-5-32-550", "BO": "S-1-5-32-551",
	"RE": "S-1-5-32-552", "RU": "S-1-5-32-554", "RD": "S-1-5-32-555", "NO": "S-1-5-32-556",
	"MU": "S-1-5-32-558", "LU": "S-1-5-32-559", "IS": "S-1-5-32-568", "CY": "S-1-5-32-569",
	"ER": "S-1-5-32-573", "RM": "S-1-5-32-580", "HA": "S-1-5-32-578",
}

// Domain-relative SID aliases (RIDs of the domain).
var domainRIDs = map[string]int{
	"LA": 500, "LG": 501, "DA": 512, "DU": 513, "DG": 514, "DC": 515, "DD": 516, "CA": 517,
	"SA": 518, "EA": 519, "PA": 520, "RO": 498,
}

var sidRE = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,15}$`)

// resolveSID turns an alias or a SID into a SID.
func resolveSID(s, domainSID string) (string, error) {
	if sidRE.MatchString(s) {
		return s, nil
	}
	if v, ok := wellKnown[s]; ok {
		return v, nil
	}
	if rid, ok := domainRIDs[s]; ok {
		if domainSID == "" {
			return "", fmt.Errorf("sddl: alias %s needs the domain SID", s)
		}
		return domainSID + "-" + strconv.Itoa(rid), nil
	}
	return "", fmt.Errorf("sddl: unknown SID or alias %q", s)
}

func parseRights(r string) (uint32, error) {
	if strings.HasPrefix(r, "0x") || strings.HasPrefix(r, "0X") {
		v, err := strconv.ParseUint(r[2:], 16, 32)
		return uint32(v), err
	}
	if r != "" && r[0] >= '0' && r[0] <= '9' {
		v, err := strconv.ParseUint(r, 10, 32)
		return uint32(v), err
	}
	if len(r)%2 != 0 {
		return 0, fmt.Errorf("sddl: rights %q", r)
	}
	var m uint32
	for i := 0; i < len(r); i += 2 {
		v, ok := rightTokens[r[i:i+2]]
		if !ok {
			return 0, fmt.Errorf("sddl: unknown right %q", r[i:i+2])
		}
		m |= v
	}
	return m, nil
}

var flagOrder = []string{"OI", "CI", "NP", "IO", "ID", "SA", "FA"}

func parseFlags(f string) (string, error) {
	if len(f)%2 != 0 {
		return "", fmt.Errorf("sddl: flags %q", f)
	}
	var have []string
	for i := 0; i < len(f); i += 2 {
		t := f[i : i+2]
		if !slices.Contains(flagOrder, t) {
			return "", fmt.Errorf("sddl: unknown ACE flag %q", t)
		}
		have = append(have, t)
	}
	var b strings.Builder
	for _, t := range flagOrder {
		if slices.Contains(have, t) {
			b.WriteString(t)
		}
	}
	return b.String(), nil
}

// Parse reads a descriptor. domainSID resolves domain-relative aliases.
func Parse(s, domainSID string) (SD, error) {
	var sd SD
	s = strings.TrimSpace(s)
	if s == "" {
		return sd, errors.New("sddl: empty")
	}
	i := 0
	for i < len(s) {
		if i+2 > len(s) || s[i+1] != ':' {
			return sd, fmt.Errorf("sddl: unexpected %q", s[i:])
		}
		part := s[i]
		i += 2
		switch part {
		case 'O', 'G':
			j := i
			for j < len(s) && !(j+1 < len(s) && s[j+1] == ':' && strings.ContainsRune("OGDS", rune(s[j]))) {
				j++
			}
			v, err := resolveSID(s[i:j], domainSID)
			if err != nil {
				return sd, err
			}
			if part == 'O' {
				sd.Owner = v
			} else {
				sd.Group = v
			}
			i = j
		case 'D', 'S':
			j := i
			for j < len(s) && s[j] != '(' && !(j+1 < len(s) && s[j+1] == ':') {
				j++
			}
			flags := s[i:j]
			var aces []ACE
			for j < len(s) && s[j] == '(' {
				k := strings.IndexByte(s[j:], ')')
				if k < 0 {
					return sd, errors.New("sddl: unterminated ACE")
				}
				ace, err := parseACE(s[j+1:j+k], domainSID)
				if err != nil {
					return sd, err
				}
				aces = append(aces, ace)
				j += k + 1
			}
			if part == 'D' {
				sd.HasDACL = true
				sd.Protected = strings.Contains(flags, "P")
				sd.AutoInherited = strings.Contains(flags, "AI")
				sd.DACL = aces
			}
			i = j
		default:
			return sd, fmt.Errorf("sddl: unknown part %q", part)
		}
	}
	return sd, nil
}

func parseACE(s, domainSID string) (ACE, error) {
	f := strings.Split(s, ";")
	if len(f) < 6 {
		return ACE{}, fmt.Errorf("sddl: ACE %q", s)
	}
	flags, err := parseFlags(f[1])
	if err != nil {
		return ACE{}, err
	}
	mask, err := parseRights(f[2])
	if err != nil {
		return ACE{}, err
	}
	sid, err := resolveSID(f[5], domainSID)
	if err != nil {
		return ACE{}, err
	}
	return ACE{Type: f[0], Flags: flags, Mask: mask, SID: sid}, nil
}

// String renders the descriptor with full SIDs and hex masks.
func (sd SD) String() string {
	var b strings.Builder
	if sd.Owner != "" {
		b.WriteString("O:" + sd.Owner)
	}
	if sd.Group != "" {
		b.WriteString("G:" + sd.Group)
	}
	if sd.HasDACL {
		b.WriteString("D:")
		if sd.Protected {
			b.WriteString("P")
		}
		if sd.AutoInherited {
			b.WriteString("AI")
		}
		for _, a := range sd.DACL {
			b.WriteString(a.String())
		}
	}
	return b.String()
}

// String renders one ACE.
func (a ACE) String() string {
	return fmt.Sprintf("(%s;%s;0x%08x;;;%s)", a.Type, a.Flags, a.Mask, a.SID)
}

func aceKey(a ACE) string { return a.String() }

// EqualACL reports whether two DACLs hold the same entries (order ignored:
// Samba keeps them as written, but an editor may reorder allow entries).
func EqualACL(a, b []ACE) bool {
	if len(a) != len(b) {
		return false
	}
	ka, kb := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		ka[i], kb[i] = aceKey(a[i]), aceKey(b[i])
	}
	slices.Sort(ka)
	slices.Sort(kb)
	return slices.Equal(ka, kb)
}

// Equal reports whether two descriptors grant the same: owner, group,
// protection and DACL entries.
func Equal(a, b SD) bool {
	return a.Owner == b.Owner && a.Group == b.Group && a.Protected == b.Protected && a.HasDACL == b.HasDACL && EqualACL(a.DACL, b.DACL)
}

// FileRights names a file-system mask: full, modify, read (read & execute)
// or the hex mask.
func FileRights(m uint32) string {
	switch m {
	case FileAll:
		return "full"
	case FileModify:
		return "modify"
	case FileReadEx:
		return "read"
	case FileRead:
		return "read (no traverse)"
	}
	return fmt.Sprintf("0x%08x", m)
}

// ShareRights names a share mask: FULL, CHANGE, READ or the hex mask.
func ShareRights(m uint32) string {
	switch m {
	case ShareFull:
		return "FULL"
	case ShareChange:
		return "CHANGE"
	case ShareRead:
		return "READ"
	}
	return fmt.Sprintf("0x%08x", m)
}

// TypeName names an ACE type for display.
func TypeName(t string) string {
	switch t {
	case "A":
		return "allow"
	case "D":
		return "deny"
	}
	return t
}

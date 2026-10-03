package sddl

import "testing"

const dom = "S-1-5-21-2731809216-992630030-2226254955"

func TestParseSambaOutput(t *testing.T) {
	// What samba-tool ntacl get --as-sddl printed in the lab after our write.
	got, err := Parse("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;DA)(A;OICI;0x1301bf;;;"+dom+"-4105)", dom)
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != "S-1-5-32-544" || got.Group != "S-1-5-32-544" || !got.Protected || !got.AutoInherited || len(got.DACL) != 4 {
		t.Fatalf("%+v", got)
	}
	if got.DACL[2].SID != dom+"-512" || got.DACL[3].Mask != FileModify || got.DACL[3].Flags != "OICI" {
		t.Fatalf("%+v", got.DACL)
	}
	// The same descriptor as conductor-files writes it (full SIDs, hex).
	want := SD{Owner: "S-1-5-32-544", Group: "S-1-5-32-544", Protected: true, AutoInherited: true, HasDACL: true, DACL: []ACE{
		{"A", "OICI", FileAll, "S-1-5-18"}, {"A", "OICI", FileAll, "S-1-5-32-544"}, {"A", "OICI", FileAll, dom + "-512"},
		{"A", "OICI", FileModify, dom + "-4105"}}}
	if !Equal(got, want) {
		t.Fatalf("not equal:\n%s\n%s", got, want)
	}
	back, err := Parse(want.String(), dom)
	if err != nil || !Equal(back, want) {
		t.Fatalf("round trip: %v %s", err, back)
	}
	// Order of entries does not matter; content does.
	swapped := want
	swapped.DACL = []ACE{want.DACL[3], want.DACL[0], want.DACL[1], want.DACL[2]}
	if !Equal(swapped, want) {
		t.Fatal("order must not matter")
	}
	changed := want
	changed.DACL = append([]ACE(nil), want.DACL...)
	changed.DACL[3].Mask = FileReadEx
	if Equal(changed, want) {
		t.Fatal("a different mask must differ")
	}
	unprotected := want
	unprotected.Protected = false
	if Equal(unprotected, want) {
		t.Fatal("protection must matter")
	}
}

func TestParseDefaultsAndShareACLs(t *testing.T) {
	// Samba's default for a new directory and sharesec --viewsddl output.
	sd, err := Parse("O:S-1-22-1-0G:S-1-22-2-0D:(A;;FA;;;S-1-22-1-0)(A;;0x1200a9;;;S-1-22-2-0)(A;;0x1200a9;;;WD)(A;OICIIO;FA;;;CO)(A;OICIIO;0x1200a9;;;CG)", dom)
	if err != nil || len(sd.DACL) != 5 || sd.DACL[3].Flags != "OICIIO" || sd.DACL[2].SID != "S-1-1-0" {
		t.Fatalf("%v %+v", err, sd)
	}
	share, err := Parse("D:(A;;FA;;;BA)(A;;FA;;;"+dom+"-512)(A;;0x1301ff;;;"+dom+"-4105)", dom)
	if err != nil || share.Owner != "" || len(share.DACL) != 3 || ShareRights(share.DACL[2].Mask) != "CHANGE" {
		t.Fatalf("%v %+v", err, share)
	}
	if FileRights(FileReadEx) != "read" || FileRights(FileModify) != "modify" || FileRights(FileAll) != "full" || FileRights(0x10) != "0x00000010" {
		t.Fatal("file rights names")
	}
	if m, err := parseRights("GRGX"); err != nil || m != 0xa0000000 {
		t.Fatalf("generic rights %x %v", m, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"", "X:BA", "O:ZZ", "D:(A;;FA;;;BA", "D:(A;;QQ;;;BA)", "D:(A;XX;FA;;;BA)", "D:(A;;FA;;BA)", "O:DA"} {
		d := dom
		if s == "O:DA" {
			d = ""
		}
		if _, err := Parse(s, d); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;" + dom + "-4105)")
	f.Add("D:(A;;FA;;;WD)")
	f.Fuzz(func(t *testing.T, s string) {
		sd, err := Parse(s, dom)
		if err != nil || sd.String() == "" {
			return // nothing modelled (e.g. only a SACL)
		}
		back, err := Parse(sd.String(), dom)
		if err != nil || !Equal(sd, back) {
			t.Fatalf("round trip of %q: %v", s, err)
		}
	})
}

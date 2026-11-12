package store

import (
	"reflect"
	"slices"
	"testing"
)

func targets(names ...string) []Target {
	out := make([]Target, len(names))
	for i, n := range names {
		out[i] = Target{Namespace: n, Name: "billing", Scope: "strict"}
	}
	return out
}

func TestEffective(t *testing.T) {
	all := Change{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01A",
		Targets: targets("use1-blue", "use1-green", "use2-blue"), Ciphertexts: []string{"a1", "a2", "a3"}}
	use1 := Change{ID: "use1", Path: "a.yaml", Key: "token", CommandID: "01B", Regions: []string{"use1"},
		Targets: targets("use1-blue", "use1-green"), Ciphertexts: []string{"b1", "b2"}}
	other := Change{ID: "other", Path: "a.yaml", Key: "url", CommandID: "01C",
		Targets: targets("use1-blue", "use1-green", "use2-blue")}

	tests := map[string]struct {
		in   []Change
		want []Change
	}{
		"nothing overlaps": {
			in:   []Change{all, other},
			want: []Change{all, other},
		},
		"a newer seal for a region wins there": {
			in: []Change{all, use1},
			want: []Change{
				{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01A",
					Targets: targets("use2-blue"), Ciphertexts: []string{"a3"}},
				use1,
			},
		},
		"a newer seal for every document leaves the older one out": {
			in: []Change{use1, {ID: "all", Path: "a.yaml", Key: "token", CommandID: "01D",
				Targets: all.Targets, Ciphertexts: all.Ciphertexts}},
			want: []Change{{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01D",
				Targets: all.Targets, Ciphertexts: all.Ciphertexts}},
		},
		"other keys and files are apart": {
			in:   []Change{use1, other, {ID: "f", Path: "b.yaml", Key: "token", CommandID: "01E", Targets: targets("use1-blue")}},
			want: []Change{use1, other, {ID: "f", Path: "b.yaml", Key: "token", CommandID: "01E", Targets: targets("use1-blue")}},
		},
		"listings without ciphertexts stay without": {
			in: []Change{
				{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01A", Targets: all.Targets},
				{ID: "use1", Path: "a.yaml", Key: "token", CommandID: "01B", Targets: use1.Targets},
			},
			want: []Change{
				{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01A", Targets: targets("use2-blue")},
				{ID: "use1", Path: "a.yaml", Key: "token", CommandID: "01B", Targets: use1.Targets},
			},
		},
		"none": {in: nil, want: []Change{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Effective(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Effective() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

// regional are one document per region, as copies of a secret usually are:
// the same namespace and name, told apart by their place in the file.
func regional(regions ...string) []Target {
	out := make([]Target, len(regions))
	for i, r := range regions {
		out[i] = Target{Index: indexOf(r), Namespace: "billing", Name: "billing", Scope: "strict", Region: r}
	}
	return out
}

// indexOf places each region's document in a fixed spot in the file.
func indexOf(region string) *int {
	i := map[string]int{"use1": 0, "use2": 1, "usw2": 2}[region]
	return &i
}

func TestEffective_SameNameInEachRegion(t *testing.T) {
	use1 := Change{ID: "use1", Path: "a.yaml", Key: "token", CommandID: "01A", Regions: []string{"use1"},
		Targets: regional("use1"), Ciphertexts: []string{"a1"}}
	use2 := Change{ID: "use2", Path: "a.yaml", Key: "token", CommandID: "01B", Regions: []string{"use2"},
		Targets: regional("use2"), Ciphertexts: []string{"b2"}}
	all := Change{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01C",
		Targets: regional("use1", "use2"), Ciphertexts: []string{"c1", "c2"}}

	// a value for each region: both apply
	if got := Effective([]Change{use1, use2}); !reflect.DeepEqual(got, []Change{use1, use2}) {
		t.Errorf("one value per region = %+v", got)
	}
	// every region, then one: the older keeps the other region
	newer := use1
	newer.CommandID = "01D"
	want := []Change{{ID: "all", Path: "a.yaml", Key: "token", CommandID: "01C",
		Targets: regional("use2"), Ciphertexts: []string{"c2"}}, newer}
	if got := Effective([]Change{all, newer}); !reflect.DeepEqual(got, want) {
		t.Errorf("all, then use1 =\n%+v\nwant\n%+v", got, want)
	}

	// changes stored before targets had positions are told apart by region
	old := func(c Change) Change {
		c.Targets = append([]Target(nil), c.Targets...)
		for i := range c.Targets {
			c.Targets[i].Index = nil
		}
		return c
	}
	if got := Effective([]Change{old(use1), old(use2)}); len(got) != 2 {
		t.Errorf("stored without positions = %+v", got)
	}
	// and a newer change with positions still takes over their documents
	if got := Effective([]Change{old(use1), all}); !reflect.DeepEqual(got, []Change{all}) {
		t.Errorf("an old change under a newer one = %+v", got)
	}
}

func TestSuperseded(t *testing.T) {
	change := func(id, cmd string, regions ...string) Change {
		return Change{ID: id, Path: "a.yaml", Key: "token", CommandID: cmd, Targets: regional(regions...)}
	}
	ids := func(cs []Change) []string {
		out := []string{}
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	tests := map[string]struct {
		in   []Change
		want []string
	}{
		"a newer change for the same documents": {
			in:   []Change{change("use1", "01A", "use1"), change("all", "01B", "use1", "use2")},
			want: []string{"use1"},
		},
		"newer changes only between them": {
			in: []Change{change("all", "01A", "use1", "use2"),
				change("use1", "01B", "use1"), change("use2", "01C", "use2")},
			want: []string{},
		},
		"an older change covers nothing newer": {
			in:   []Change{change("all", "01A", "use1", "use2"), change("use1", "01B", "use1")},
			want: []string{},
		},
		"other keys": {
			in: []Change{change("use1", "01A", "use1"),
				{ID: "url", Path: "a.yaml", Key: "url", CommandID: "01B", Targets: regional("use1")}},
			want: []string{},
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := ids(Superseded(tt.in)); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Superseded() = %v, want %v", got, tt.want)
			}
		})
	}
}

// A value sealed in the session wins over a reseal of the same key and
// document, whichever came first: the reseal moved the value the file held
// before.
func TestEffective_SealWinsOverReseal(t *testing.T) {
	seal := Change{ID: "seal", Path: "a.yaml", Key: "token", CommandID: "01A",
		Targets: targets("use1-blue"), Ciphertexts: []string{"sealed"}}
	reseal := Change{ID: "reseal", Path: "a.yaml", Key: "token", CommandID: "01B", Kind: ChangeReseal,
		Targets: targets("use1-blue", "use2-blue"), Ciphertexts: []string{"r1", "r2"}}
	want := []Change{seal, reseal}
	want[1].Targets, want[1].Ciphertexts = targets("use2-blue"), []string{"r2"}
	if got := Effective([]Change{seal, reseal}); !reflect.DeepEqual(got, want) {
		t.Errorf("an older seal under a newer reseal = %+v", got)
	}
	// a newer reseal never supersedes a seal; a seal covering a reseal
	// does, older or newer
	covered := reseal
	covered.Targets, covered.Ciphertexts = targets("use1-blue"), []string{"r1"}
	if got := Superseded([]Change{seal, covered}); len(got) != 1 || got[0].ID != "reseal" {
		t.Errorf("Superseded = %+v", got)
	}
	// reseals among themselves: the newer wins
	newer := covered
	newer.ID, newer.CommandID = "reseal-2", "01C"
	if got := Superseded([]Change{covered, newer}); len(got) != 1 || got[0].ID != "reseal" {
		t.Errorf("Superseded of two reseals = %+v", got)
	}
	// written in this order, the seal is written last
	if CompareRank(seal, reseal) != 1 || CompareRank(reseal, seal) != -1 || CompareRank(covered, newer) != -1 {
		t.Error("CompareRank does not put the change that wins last")
	}
}

// Targets stored before documents could list several regions name one;
// they read as a list of it, and match a document by name as before.
func TestTargetRegionList(t *testing.T) {
	old := Target{Namespace: "apps", Name: "billing", Region: "use1"}
	if got := old.RegionList(); !slices.Equal(got, []string{"use1"}) {
		t.Errorf("old target's regions = %q", got)
	}
	both := Target{Regions: []string{"use1", "use2"}}
	if got := both.RegionList(); !slices.Equal(got, []string{"use1", "use2"}) {
		t.Errorf("regions = %q", got)
	}
	if got := (Target{}).RegionList(); got != nil {
		t.Errorf("no regions = %q", got)
	}
	c := Change{Path: "a.yaml", Key: "k"}
	if byName(c, old) != byName(c, Target{Namespace: "apps", Name: "billing", Regions: []string{"use1"}}) {
		t.Error("an old target and a new one for the same document differ")
	}
}

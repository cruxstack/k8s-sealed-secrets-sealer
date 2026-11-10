package store

import (
	"reflect"
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

package store

import "slices"

// Outranks reports whether change a wins over change b where both set a
// document's key: a value sealed in the session always wins over a reseal,
// whatever their order, since the reseal moved the value the file held
// before; otherwise the newer wins (command IDs are ULIDs).
func Outranks(a, b Change) bool {
	if a.Resealed() != b.Resealed() {
		return !a.Resealed()
	}
	return a.CommandID > b.CommandID
}

// Effective returns pending changes as they apply. Changes of one file and
// key may overlap, when values were sealed for some regions and then others
// or all: for each document, the newest seal wins, and a seal wins over a
// reseal (Outranks). A change keeps only the
// targets no newer change of its file and key also targets, with their
// ciphertexts when they were read; a change left without targets is left
// out. The result keeps the input's order.
func Effective(changes []Change) []Change {
	claimed := docSet{}
	kept := make([]Change, len(changes))
	for _, i := range newestFirst(changes) {
		c := changes[i]
		withCiphertexts := len(c.Ciphertexts) == len(c.Targets)
		var targets []Target
		var ciphertexts []string
		for j, t := range c.Targets {
			if claimed.has(c, t) {
				continue
			}
			claimed.add(c, t)
			targets = append(targets, t)
			if withCiphertexts {
				ciphertexts = append(ciphertexts, c.Ciphertexts[j])
			}
		}
		c.Targets = targets
		if withCiphertexts {
			c.Ciphertexts = ciphertexts
		}
		kept[i] = c
	}
	out := make([]Change, 0, len(changes))
	for _, c := range kept {
		if len(c.Targets) > 0 {
			out = append(out, c)
		}
	}
	return out
}

// Superseded returns the changes one newer change of the same file and key
// covers entirely: they can no longer apply, whatever else is removed. A
// change that newer ones only cover between them is not superseded, since
// removing one of those brings it back where that one applied.
func Superseded(changes []Change) []Change {
	var out []Change
	for _, old := range changes {
		if len(old.Targets) == 0 {
			continue
		}
		for _, c := range changes {
			if !Outranks(c, old) || c.Path != old.Path || c.Key != old.Key {
				continue
			}
			covers := docSet{}
			for _, t := range c.Targets {
				covers.add(c, t)
			}
			if !slices.ContainsFunc(old.Targets, func(t Target) bool { return !covers.has(old, t) }) {
				out = append(out, old)
				break
			}
		}
	}
	return out
}

// newestFirst returns the changes' indexes, the change that wins first
// (Outranks).
func newestFirst(changes []Change) []int {
	order := make([]int, len(changes))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return -CompareRank(changes[a], changes[b]) })
	return order
}

// CompareRank orders changes the way they apply: a change before those
// that win over it (Outranks), so writing them in order leaves the winner.
func CompareRank(a, b Change) int {
	switch {
	case Outranks(a, b):
		return 1
	case Outranks(b, a):
		return -1
	}
	return 0
}

// docRef names one document of a file for one key: by its position in the
// file when the target records it, or else by region, namespace and name.
// Copies of a secret in several regions often share a namespace and name,
// so those alone do not tell documents apart.
type docRef struct {
	path, key string
	byIndex   bool
	index     int
	region    string
	namespace string
	name      string
}

// docSet is a set of documents that changes target.
type docSet map[docRef]bool

func (s docSet) has(c Change, t Target) bool {
	if t.Index != nil {
		return s[docRef{path: c.Path, key: c.Key, byIndex: true, index: *t.Index}]
	}
	return s[byName(c, t)]
}

// add records a target's document under both names, so a change stored
// before targets recorded positions still finds it.
func (s docSet) add(c Change, t Target) {
	if t.Index != nil {
		s[docRef{path: c.Path, key: c.Key, byIndex: true, index: *t.Index}] = true
	}
	s[byName(c, t)] = true
}

func byName(c Change, t Target) docRef {
	return docRef{path: c.Path, key: c.Key, region: t.Region, namespace: t.Namespace, name: t.Name}
}

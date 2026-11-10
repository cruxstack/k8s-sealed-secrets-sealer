package store

import "slices"

// Effective returns pending changes as they apply. Changes of one file and
// key may overlap, when values were sealed for some regions and then others
// or all: for each document, the newest seal wins. A change keeps only the
// targets no newer change of its file and key also targets, with their
// ciphertexts when they were read; a change left without targets is left
// out. The result keeps the input's order.
func Effective(changes []Change) []Change {
	type doc struct{ path, key, namespace, name string }
	// newest first: command IDs are ULIDs, so they sort by time
	order := make([]int, len(changes))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int {
		switch ca, cb := changes[a].CommandID, changes[b].CommandID; {
		case ca > cb:
			return -1
		case ca < cb:
			return 1
		}
		return 0
	})
	claimed := map[doc]bool{}
	kept := make([]Change, len(changes))
	for _, i := range order {
		c := changes[i]
		withCiphertexts := len(c.Ciphertexts) == len(c.Targets)
		var targets []Target
		var ciphertexts []string
		for j, t := range c.Targets {
			d := doc{c.Path, c.Key, t.Namespace, t.Name}
			if claimed[d] {
				continue
			}
			claimed[d] = true
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

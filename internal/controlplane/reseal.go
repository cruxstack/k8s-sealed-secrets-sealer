package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// Resealing moves values off older keys onto the env key, without
// decrypting them (docs/design.md, "Resealing"). A reseal.v1 command carries
// whole keys of a file: every value of a key in the file's documents goes in
// the same command, so each command's result makes whole changes.

// Reseal limits.
const (
	// resealCommandTTL is how long a reseal waits to be leased and run, as
	// long as key commands.
	resealCommandTTL = keyCommandTTL
	// resealChangeHold is how long a reseal holds places among its
	// session's pending changes: until its commands expire, and a minute
	// for results recorded as they do.
	resealChangeHold = resealCommandTTL + time.Minute
	// maxResealBody bounds a request to reseal a file.
	maxResealBody = 4 << 10
	// maxResealFailures bounds the failures listed for a file reseal or a
	// run's repository.
	maxResealFailures = 50
	// maxResealCiphertextChars bounds one resealed value, base64: a value
	// alone fills a command at most.
	maxResealCiphertextChars = protocol.ResealBudgetBytes
)

// errTooLargeToReseal is why the values of a key too large for one command
// are not resealed.
const errTooLargeToReseal = "the key's values in this file are too large to reseal together; seal it again"

// resealValue is one value of a file to reseal: where it is and what it is.
type resealValue struct {
	file int
	doc  manifest.Document
	key  string
	// ciphertext is the value as it is in spec.encryptedData
	ciphertext string
}

// item is the value as a reseal.v1 item.
func (v resealValue) item() protocol.ResealItem {
	return protocol.ResealItem{
		ID:         resealItemID(v.file, v.doc.Index, v.key),
		Namespace:  v.doc.Namespace,
		Name:       v.doc.Name,
		Scope:      v.doc.Scope,
		Ciphertext: v.ciphertext,
	}
}

// resealItemID names a value in a command: its file (by its place in what a
// run reads, 0 in a session), its document's position and its key. Keys
// are Secret keys, which hold no slash.
func resealItemID(file, doc int, key string) string {
	return strconv.Itoa(file) + "/" + strconv.Itoa(doc) + "/" + key
}

// parseResealItemID reads a resealItemID.
func parseResealItemID(id string) (file, doc int, key string, ok bool) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 {
		return 0, 0, "", false
	}
	file, errFile := strconv.Atoi(parts[0])
	doc, errDoc := strconv.Atoi(parts[1])
	return file, doc, parts[2], errFile == nil && errDoc == nil && parts[2] != ""
}

// resealGroup is the values of one key in one file. A command carries whole
// groups, so a key's change is made from one command's result.
type resealGroup struct {
	file   int
	key    string
	values []resealValue
}

func (g resealGroup) cost() int {
	n := 0
	for _, v := range g.values {
		n += protocol.ResealItemCost(len(v.ciphertext))
	}
	return n
}

// resealPlan is what resealing a file's values for the env sends.
type resealPlan struct {
	groups []resealGroup
	// total counts the values of the file's documents for the env, and
	// pending those a pending change of the session sets
	total, pending int
	// failures are values that cannot be sent
	failures []store.ResealFailure
	// docs are the documents values are sent from
	docs []manifest.Document
}

// planReseal lists what to reseal in a file: every value of its documents
// for the env, by key, except those skip says to leave out. A value of a
// document that cannot be sealed into, or that is not a valid sealed
// value's place, fails here; the agent finds which of the rest it can
// reseal.
func planReseal(file int, path string, docs []manifest.Document, values []map[string]string, skip func(manifest.Document, string) bool) resealPlan {
	var p resealPlan
	byKey := map[string]*resealGroup{}
	var keys []string
	sent := map[int]bool{}
	for i, d := range docs {
		var vals map[string]string
		if i < len(values) {
			vals = values[i]
		}
		for _, key := range d.Keys {
			p.total++
			ct, ok := vals[key]
			switch {
			case skip != nil && skip(d, key):
				p.pending++
				continue
			case !d.Sealable():
				p.failures = append(p.failures, failure(path, d, key, "the document cannot be resealed: "+d.Problem))
				continue
			case len(validation.IsConfigMapKey(key)) > 0:
				p.failures = append(p.failures, failure(path, d, key, "not a valid Secret key"))
				continue
			case !ok || ct == "":
				p.failures = append(p.failures, failure(path, d, key, "not a sealed value"))
				continue
			}
			g := byKey[key]
			if g == nil {
				g = &resealGroup{file: file, key: key}
				byKey[key] = g
				keys = append(keys, key)
			}
			g.values = append(g.values, resealValue{file: file, doc: d, key: key, ciphertext: ct})
			if !sent[d.Index] {
				sent[d.Index] = true
				p.docs = append(p.docs, d)
			}
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		p.groups = append(p.groups, *byKey[k])
	}
	return p
}

func failure(path string, d manifest.Document, key, msg string) store.ResealFailure {
	return store.ResealFailure{Path: path, Key: key, Document: d.Index, Region: d.Region, Error: msg}
}

// packReseal packs groups into commands of at most protocol.MaxResealItems
// items and protocol.ResealBudgetBytes, in order. A group too large for a
// command of its own is returned apart: its values cannot be resealed
// together.
func packReseal(groups []resealGroup) (packs [][]resealGroup, tooLarge []resealGroup) {
	var cur []resealGroup
	items, cost := 0, 0
	for _, g := range groups {
		gc := g.cost()
		if len(g.values) > protocol.MaxResealItems || gc > protocol.ResealBudgetBytes {
			tooLarge = append(tooLarge, g)
			continue
		}
		if len(cur) > 0 && (items+len(g.values) > protocol.MaxResealItems || cost+gc > protocol.ResealBudgetBytes) {
			packs = append(packs, cur)
			cur, items, cost = nil, 0, 0
		}
		cur = append(cur, g)
		items += len(g.values)
		cost += gc
	}
	if len(cur) > 0 {
		packs = append(packs, cur)
	}
	return packs, tooLarge
}

// resealPayload is the reseal.v1 payload of a pack.
func resealPayload(envKey string, pack []resealGroup) protocol.ResealPayload {
	p := protocol.ResealPayload{EnvKey: envKey}
	for _, g := range pack {
		for _, v := range g.values {
			p.Items = append(p.Items, v.item())
		}
	}
	return p
}

// resealCommand returns a reseal.v1 command for an agent, its payload kept
// apart from the agent's commands (store.CommandRecord.ExternalPayload).
func resealCommand(agentID, id string, p protocol.ResealPayload, now time.Time) (store.CommandRecord, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return store.CommandRecord{}, fmt.Errorf("failed to encode reseal payload: %w", err)
	}
	return store.CommandRecord{
		AgentID:         agentID,
		ID:              id,
		Type:            protocol.CommandReseal,
		Status:          store.CommandQueued,
		CreatedAt:       now,
		ExpiresAt:       now.Add(resealCommandTTL),
		Payload:         string(body),
		ExternalPayload: true,
	}, nil
}

// resealChangeID is the ID of the pending change a file reseal makes for a
// key: one of its own, so it never replaces a value sealed in the session,
// and a newer seal of the key covers it as any newer seal does.
func resealChangeID(path, key, resealID string) string {
	sum := sha256.Sum256([]byte("reseal\x00" + path + "\x00" + key + "\x00" + resealID))
	return hex.EncodeToString(sum[:16])
}

// checkResealResult checks that a result has an outcome for each item the
// command carried, in order. A resealed value must be base64 whose AES-GCM
// part, after its RSA part, is the value's own byte for byte: only its
// one-time key may be wrapped anew, never the value changed.
func checkResealResult(p protocol.ResealPayload, raw json.RawMessage, res *protocol.ResealResult) error {
	// fields a newer agent adds are ignored, as in every agent message
	if len(raw) == 0 || json.Unmarshal(raw, res) != nil {
		return errors.New("not a reseal result")
	}
	if len(res.Items) != len(p.Items) {
		return fmt.Errorf("%d outcomes for %d items", len(res.Items), len(p.Items))
	}
	for i, it := range res.Items {
		in := p.Items[i]
		if it.ID != in.ID {
			return fmt.Errorf("item %d is %q, want %q", i, it.ID, in.ID)
		}
		switch it.Status {
		case protocol.ResealCurrent, protocol.ResealFailed:
			if it.Ciphertext != "" {
				return fmt.Errorf("item %d is %s but has a ciphertext", i, it.Status)
			}
			if len(it.Error) > maxResultError {
				return fmt.Errorf("item %d's error is too long", i)
			}
		case protocol.ResealResealed:
			if !strings.HasPrefix(it.From, "SHA256:") || len(it.From) > 128 || it.From == p.EnvKey {
				return fmt.Errorf("item %d names no key it came off", i)
			}
			if it.Ciphertext == "" || len(it.Ciphertext) > maxResealCiphertextChars {
				return fmt.Errorf("item %d has no usable ciphertext", i)
			}
			if !sameSealedPart(in.Ciphertext, it.Ciphertext) {
				return fmt.Errorf("item %d is not the same value", i)
			}
		default:
			return fmt.Errorf("item %d has status %q", i, it.Status)
		}
	}
	return nil
}

// sameSealedPart reports whether two base64 sealed values have the same
// AES-GCM part, after their RSA parts.
func sameSealedPart(a, b string) bool {
	pa, okA := sealedPart(a)
	pb, okB := sealedPart(b)
	return okA && okB && bytes.Equal(pa, pb)
}

func sealedPart(b64 string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(raw))
	if n == 0 || len(raw) < 2+n {
		return nil, false
	}
	return raw[2+n:], true
}

// resealCounts counts a result's items by outcome.
func resealCounts(res protocol.ResealResult) store.ResealCounts {
	var c store.ResealCounts
	for _, it := range res.Items {
		switch it.Status {
		case protocol.ResealResealed:
			c.Resealed++
		case protocol.ResealCurrent:
			c.Current++
		default:
			c.Failed++
		}
	}
	return c
}

// chooseResealer picks the agent for a reseal and returns it with the env
// key, as chooseSealer does for a seal.
func (s *Server) chooseResealer(ctx context.Context, regions []string, now time.Time) (fleet.Agent, string, error) {
	return s.chooseAgent(ctx, regions, now, fleet.ChooseResealer)
}

// resealRefusal says why no reseal can start, for a 409, and whether one
// was refused for that.
func resealRefusal(err error) (string, bool) {
	var outOfSync *fleet.KeysOutOfSyncError
	switch {
	case errors.As(err, &outOfSync), errors.Is(err, fleet.ErrNoUsableKey):
		return "there is no env key to reseal with: " + err.Error(), true
	case errors.Is(err, fleet.ErrNoResealer), errors.Is(err, fleet.ErrEnvKeyNotActive):
		return err.Error(), true
	}
	return "", false
}

// regionsOf returns the documents' regions, for choosing an agent there.
func regionsOf(docs []manifest.Document) []string {
	var out []string
	for _, d := range docs {
		if d.Region != "" && !slices.Contains(out, d.Region) {
			out = append(out, d.Region)
		}
	}
	return out
}

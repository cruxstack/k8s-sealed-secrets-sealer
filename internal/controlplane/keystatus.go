package controlplane

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// adminTokenActor names whoever used the admin token, in key status changes.
const adminTokenActor = "admin token"

// deletedKeyRetention is how long a deleted key's escrowed copies are kept,
// and so how long the deletion can be undone by reinstating the key.
const deletedKeyRetention = 30 * 24 * time.Hour

// keyStatusView is a key's status, as revoking, reinstating and deleting
// return it. PurgeAt is set on a deleted key: when its escrowed copies are
// purged.
type keyStatusView struct {
	Fingerprint string     `json:"fingerprint"`
	Status      string     `json:"status"`
	StatusBy    string     `json:"status_by,omitempty"`
	StatusAt    *time.Time `json:"status_at,omitempty"`
	PurgeAt     *time.Time `json:"purge_at,omitempty"`
}

// Why a key status change is refused (409). A delete is refused with the
// sentence the fleet view gives as the key's delete_blocked.
const (
	refuseDeleteActive    = fleet.BlockedActive
	refuseDeleteDeleted   = fleet.BlockedDeleted
	refuseRevokeDeleted   = "The key is deleted; reinstate it to make it active again."
	refuseReinstatePurged = "Its escrowed copies were purged; it cannot be reinstated."
	refuseKeyChanged      = "The key changed meanwhile; reload and try again."
)

// requestedKey reads the key a key status request names. It answers 404 for
// a fingerprint that is malformed or not the env's, and reports whether it
// found one.
func (s *Server) requestedKey(w http.ResponseWriter, r *http.Request) (store.KeyRecord, bool) {
	fp := protocol.ParseFingerprintPath(r.PathValue("fingerprint"))
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 128 {
		writeError(w, http.StatusNotFound, "no such key in this env")
		return store.KeyRecord{}, false
	}
	key, ok, err := s.store.GetKey(r.Context(), fp)
	if err != nil {
		s.internalError(w, r, "failed to read key", err)
		return store.KeyRecord{}, false
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such key in this env")
		return store.KeyRecord{}, false
	}
	return key, true
}

// actor names who changes a key: the signed-in admin, or the admin token.
func actor(ctx context.Context) string {
	if u := userauth.UserFrom(ctx); u != nil {
		return u.Login
	}
	return adminTokenActor
}

// setKeyStatus revokes a key (store.KeyRevoked) or reinstates one
// (store.KeyActive), for an admin. Revoking only changes what this control
// plane does with the key: it is never the env key, never restored and
// never counted as missing. Clusters keep it, and its escrowed copies are
// kept, so reinstating undoes it. Setting the status a key has already
// changes nothing. A deleted key cannot be revoked; reinstating it undoes
// the deletion until its escrowed copies are purged.
func (s *Server) setKeyStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		key, ok := s.requestedKey(w, r)
		if !ok {
			return
		}
		if key.Status == store.KeyDeleted {
			if status == store.KeyRevoked {
				writeError(w, http.StatusConflict, refuseRevokeDeleted)
				return
			}
			s.reinstateDeleted(w, r, key)
			return
		}
		if current := key.Status; current == status || (current == "" && status == store.KeyActive) {
			httpserver.WriteJSON(w, http.StatusOK, statusOf(key))
			return
		}

		by := actor(ctx)
		now := s.now().UTC()
		key.Status, key.StatusBy, key.StatusAt = status, by, &now
		ok, err := s.store.SetKeyStatus(ctx, key)
		switch {
		case errors.Is(err, store.ErrKeyChanged):
			// deleted meanwhile
			writeError(w, http.StatusConflict, refuseKeyChanged)
			return
		case err != nil || !ok:
			s.internalError(w, r, "failed to set key status", err)
			return
		}
		event, msg := "key.revoked", "sealing key revoked"
		if status == store.KeyActive {
			event, msg = "key.reinstated", "sealing key reinstated"
		}
		s.logger.WarnContext(ctx, msg,
			"event", event, "env", s.env, "fingerprint", key.Fingerprint, "user", by, "not_before", key.NotBefore)
		httpserver.WriteJSON(w, http.StatusOK, statusOf(key))
	}
}

// reinstateDeleted makes a deleted key active again, while its escrowed
// copies are kept: key sync then restores it to every cluster from escrow.
func (s *Server) reinstateDeleted(w http.ResponseWriter, r *http.Request, key store.KeyRecord) {
	ctx := r.Context()
	now := s.now().UTC()
	if key.PurgeAt == nil || !now.Before(*key.PurgeAt) {
		writeError(w, http.StatusConflict, refuseReinstatePurged)
		return
	}
	by := actor(ctx)
	key.Status, key.StatusBy, key.StatusAt, key.PurgeAt = store.KeyActive, by, &now, nil
	err := s.store.ReinstateDeletedKey(ctx, key)
	switch {
	case errors.Is(err, store.ErrKeyChanged):
		writeError(w, http.StatusConflict, refuseKeyChanged)
		return
	case err != nil:
		s.internalError(w, r, "failed to reinstate key", err)
		return
	}
	s.logger.WarnContext(ctx, "deleted sealing key reinstated",
		"event", "key.reinstated", "env", s.env, "fingerprint", key.Fingerprint, "user", by,
		"not_before", key.NotBefore, "was", store.KeyDeleted)
	httpserver.WriteJSON(w, http.StatusOK, statusOf(key))
}

// deleteKey deletes a revoked key, for an admin, once every cluster has
// counted no value sealed with it since it was revoked (the fleet view's
// delete gate). Agents with the cleanup capability then remove it from
// their clusters, and its escrowed copies expire deletedKeyRetention
// later; until then, reinstating it brings it back.
func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, ok := s.requestedKey(w, r)
	if !ok {
		return
	}
	switch key.Status {
	case store.KeyDeleted:
		writeError(w, http.StatusConflict, refuseDeleteDeleted)
		return
	case store.KeyRevoked:
	default:
		writeError(w, http.StatusConflict, refuseDeleteActive)
		return
	}
	now := s.now().UTC()
	f, err := s.loadFleet(ctx, now, true)
	if err != nil {
		s.internalError(w, r, "failed to read the fleet", err)
		return
	}
	k, listed := f.Key(key.Fingerprint)
	switch {
	case !listed || k.Status != store.KeyRevoked:
		// revoked records are always listed; this one changed meanwhile
		writeError(w, http.StatusConflict, refuseKeyChanged)
		return
	case !k.Deletable:
		writeError(w, http.StatusConflict, k.DeleteBlocked)
		return
	}

	// the deletion holds only for the revocation the gate checked
	var revokedAt time.Time
	if key.StatusAt != nil {
		revokedAt = *key.StatusAt
	}
	by := actor(ctx)
	purge := now.Add(deletedKeyRetention)
	key.Status, key.StatusBy, key.StatusAt, key.PurgeAt = store.KeyDeleted, by, &now, &purge
	err = s.store.DeleteKey(ctx, key, revokedAt)
	switch {
	case errors.Is(err, store.ErrKeyChanged):
		writeError(w, http.StatusConflict, refuseKeyChanged)
		return
	case err != nil:
		s.internalError(w, r, "failed to delete key", err)
		return
	}
	s.logger.WarnContext(ctx, "sealing key deleted; agents remove it from their clusters",
		"event", "key.deleted", "env", s.env, "fingerprint", key.Fingerprint, "user", by,
		"not_before", key.NotBefore, "purge_at", purge)
	httpserver.WriteJSON(w, http.StatusOK, statusOf(key))
}

// undoDeletion returns a deleted key to revoked when a cluster shows that
// values are still sealed with it, by its count or by refusing to remove
// it: its escrowed copies stop expiring, so it can be reinstated. After its
// purge time the copies may be gone, but the key, revoked again, can still
// be reinstated, and a cluster holding it escrows it anew. The agent's
// issue about the refusal stays.
func (s *Server) undoDeletion(ctx context.Context, agent *registry.Agent, r store.RevokedKey, use store.KeyUse, now time.Time) {
	err := s.store.UndeleteKey(ctx, r)
	switch {
	case errors.Is(err, store.ErrKeyChanged):
		// undone already, or reinstated
		return
	case err != nil:
		s.logger.ErrorContext(ctx, "failed to undo the deletion of a sealing key values are sealed with",
			"env", s.env, "agent_id", agent.ID, "fingerprint", r.Fingerprint, "error", err)
		return
	}
	s.forgetEscrow(r.Fingerprint)
	s.logger.WarnContext(ctx, "deletion of a sealing key undone: a cluster still has values sealed with it; it is revoked again",
		"event", "key.delete_undone", "env", s.env, "agent_id", agent.ID, "cluster", agent.Cluster,
		"fingerprint", r.Fingerprint, "values", use.Values, "sealed_secrets", use.SealedSecrets, "purged", r.Purged(now))
}

// adminTokenKeyChangesOff answers a key status change made with the admin
// token in an env that does not allow it.
func adminTokenKeyChangesOff(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusForbidden,
		"the admin token may not change keys in this env (see adminTokenKeyChanges); an admin can, from the fleet page")
}

func statusOf(k store.KeyRecord) keyStatusView {
	status := k.Status
	if status == "" {
		status = store.KeyActive
	}
	v := keyStatusView{Fingerprint: k.Fingerprint, Status: status, StatusBy: k.StatusBy, StatusAt: k.StatusAt}
	if status == store.KeyDeleted {
		v.PurgeAt = k.PurgeAt
	}
	return v
}

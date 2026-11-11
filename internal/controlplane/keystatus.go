package controlplane

import (
	"net/http"
	"strings"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// adminTokenActor names whoever used the admin token, in key status changes.
const adminTokenActor = "admin token"

// keyStatusView is a key's status, as revoking and reinstating return it.
type keyStatusView struct {
	Fingerprint string     `json:"fingerprint"`
	Status      string     `json:"status"`
	StatusBy    string     `json:"status_by,omitempty"`
	StatusAt    *time.Time `json:"status_at,omitempty"`
}

// setKeyStatus revokes a key (store.KeyRevoked) or reinstates one
// (store.KeyActive), for an admin. Revoking only changes what this control
// plane does with the key: it is never the env key, never restored and
// never counted as missing. Clusters keep it, and its escrowed copies are
// kept, so reinstating undoes it. Setting the status a key has already
// changes nothing.
func (s *Server) setKeyStatus(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		fp := protocol.ParseFingerprintPath(r.PathValue("fingerprint"))
		if !strings.HasPrefix(fp, "SHA256:") || len(fp) > 128 {
			writeError(w, http.StatusNotFound, "no such key in this env")
			return
		}
		key, ok, err := s.store.GetKey(ctx, fp)
		if err != nil {
			s.internalError(w, r, "failed to read key", err)
			return
		}
		if !ok {
			writeError(w, http.StatusNotFound, "no such key in this env")
			return
		}
		if current := key.Status; current == status || (current == "" && status == store.KeyActive) {
			httpserver.WriteJSON(w, http.StatusOK, statusOf(key))
			return
		}

		actor := adminTokenActor
		if u := userauth.UserFrom(ctx); u != nil {
			actor = u.Login
		}
		now := s.now().UTC()
		key.Status, key.StatusBy, key.StatusAt = status, actor, &now
		if ok, err := s.store.SetKeyStatus(ctx, key); err != nil || !ok {
			s.internalError(w, r, "failed to set key status", err)
			return
		}
		event, msg := "key.revoked", "sealing key revoked"
		if status == store.KeyActive {
			event, msg = "key.reinstated", "sealing key reinstated"
		}
		s.logger.WarnContext(ctx, msg,
			"event", event, "env", s.env, "fingerprint", fp, "user", actor, "not_before", key.NotBefore)
		httpserver.WriteJSON(w, http.StatusOK, statusOf(key))
	}
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
	return keyStatusView{Fingerprint: k.Fingerprint, Status: status, StatusBy: k.StatusBy, StatusAt: k.StatusAt}
}

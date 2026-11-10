package controlplane

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// requireAdmin checks the admin token. The admin API exists only when a
// token is configured, for automation; people see the fleet by signing in
// as a member of an admin team.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// fleet serves the env's fleet view: to automation holding the admin token,
// and to signed-in users who administer the env.
func (s *Server) fleet(w http.ResponseWriter, r *http.Request) {
	f, err := s.loadFleet(r.Context(), s.now().UTC())
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to read the fleet", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, f)
}

// statusView says whether sealing works, for everyone signed in. It names
// no agent or key; the fleet view, for admins, has the detail.
type statusView struct {
	Env string `json:"env"`
	// Sealing is "ready" (every cluster holds the env key and is healthy),
	// "degraded" (sealing works, but some clusters are not ready) or
	// "unavailable".
	Sealing  string `json:"sealing"`
	Message  string `json:"message"`
	Clusters struct {
		Ready int `json:"ready"`
		Total int `json:"total"`
	} `json:"clusters"`
}

// status serves whether values can be sealed in the env right now.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	f, err := s.loadFleet(r.Context(), s.now().UTC())
	if err != nil {
		s.internalError(w, r, "failed to read the fleet", err)
		return
	}
	v := statusView{Env: s.env}
	v.Clusters.Total = len(f.Agents)
	for _, a := range f.Agents {
		if a.Healthy && f.EnvKey != nil && slices.ContainsFunc(a.Keys, func(k store.KeyRef) bool {
			return k.Fingerprint == f.EnvKey.Fingerprint
		}) {
			v.Clusters.Ready++
		}
	}
	_, err = fleet.ChooseSealer(f, nil, nil)
	var outOfSync *fleet.KeysOutOfSyncError
	switch {
	case errors.As(err, &outOfSync) && len(outOfSync.Clusters) == 0:
		v.Sealing, v.Message = "unavailable", "Sealing waits for the clusters to report their keys."
	case errors.As(err, &outOfSync):
		v.Sealing = "unavailable"
		v.Message = fmt.Sprintf("Sealing is paused while key sync catches up in %d of %d clusters; this normally takes a few check-ins.",
			len(outOfSync.Clusters), v.Clusters.Total)
	case err != nil:
		v.Sealing, v.Message = "unavailable", "Sealing is unavailable: no healthy agent can seal right now."
	case v.Clusters.Ready < v.Clusters.Total || !f.KeysInSync:
		v.Sealing = "degraded"
		v.Message = fmt.Sprintf("Sealing works, but %d of %d clusters are down or missing keys.", v.Clusters.Total-v.Clusters.Ready, v.Clusters.Total)
	default:
		v.Sealing, v.Message = "ready", fmt.Sprintf("Sealing works in all %d clusters.", v.Clusters.Total)
	}
	httpserver.WriteJSON(w, http.StatusOK, v)
}

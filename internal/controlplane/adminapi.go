package controlplane

import (
	"crypto/subtle"
	"net/http"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
)

// requireAdmin checks the admin token. The admin API exists only when a
// token is configured; until user sign-in exists it is the only way to see
// the fleet.
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

func (s *Server) adminFleet(w http.ResponseWriter, r *http.Request) {
	ids := make([]string, 0, len(s.reg.Agents))
	for _, a := range s.reg.Agents {
		ids = append(ids, a.ID)
	}
	states, err := s.store.GetAgentStates(r.Context(), ids)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "failed to read agent states", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	httpserver.WriteJSON(w, http.StatusOK, fleet.Compute(s.env, s.reg, states, s.now().UTC()))
}

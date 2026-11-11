package controlplane

import (
	"context"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// recordRunResult records a reseal.v1 result of a run, for its repository.
func (s *Server) recordRunResult(ctx context.Context, cmd store.CommandRecord, p protocol.ResealPayload, res protocol.ResealResult, status, errMsg string, now time.Time) error {
	return nil
}

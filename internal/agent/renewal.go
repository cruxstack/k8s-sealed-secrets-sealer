package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Bounds on a key renew period the agent will set.
const (
	minKeyRenewPeriod = time.Hour
	maxKeyRenewPeriod = 365 * 24 * time.Hour
)

// controllerContainer is the sealed-secrets chart's container name.
const controllerContainer = "controller"

// Renewal turns on the controller's key renewal. It needs the renewal
// capability's RBAC.
type Renewal struct {
	kube       kubernetes.Interface
	namespace  string
	deployment string
	logger     *slog.Logger
}

// NewRenewal returns a Renewal. It makes no network calls.
func NewRenewal(kube kubernetes.Interface, namespace, deployment string, logger *slog.Logger) *Renewal {
	if logger == nil {
		logger = slog.Default()
	}
	return &Renewal{kube: kube, namespace: namespace, deployment: deployment, logger: logger}
}

// renewalResult is renewal.enable.v1's result.
type renewalResult struct {
	Period         string `json:"period"`
	AlreadyEnabled bool   `json:"already_enabled"`
}

// Enable runs renewal.enable.v1: it sets the controller's --key-renew-period,
// unless renewal is already on. Changing the arguments rolls the controller.
func (r *Renewal) Enable(ctx context.Context, raw json.RawMessage) (any, error) {
	var p protocol.RenewalEnablePayload
	if err := strictDecode(raw, &p); err != nil {
		return nil, err
	}
	period, err := time.ParseDuration(p.Period)
	if err != nil || period < minKeyRenewPeriod || period > maxKeyRenewPeriod {
		return nil, fmt.Errorf("invalid payload: period must be between %s and %s", minKeyRenewPeriod, maxKeyRenewPeriod)
	}

	d, err := r.kube.AppsV1().Deployments(r.namespace).Get(ctx, r.deployment, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get controller deployment %s/%s: %w", r.namespace, r.deployment, err)
	}
	i, err := controllerContainerIndex(d)
	if err != nil {
		return nil, err
	}
	c := d.Spec.Template.Spec.Containers[i]
	if current, ok := flagValue(append(slices.Clone(c.Command), c.Args...), "key-renew-period"); ok {
		if cur, err := time.ParseDuration(current); err == nil && cur > 0 {
			return renewalResult{Period: cur.String(), AlreadyEnabled: true}, nil
		}
	} else {
		// the controller's default renews every 30 days
		return renewalResult{Period: defaultKeyRenewPeriod.String(), AlreadyEnabled: true}, nil
	}

	// a flag in the arguments overrides one in the command: the last wins
	args := setFlag(c.Args, "key-renew-period", period.String())
	path := fmt.Sprintf("/spec/template/spec/containers/%d/args", i)
	patch, err := json.Marshal([]map[string]any{
		// fail if the arguments changed since they were read
		{"op": "test", "path": path, "value": c.Args},
		{"op": "replace", "path": path, "value": args},
	})
	if err != nil {
		return nil, err
	}
	if _, err := r.kube.AppsV1().Deployments(r.namespace).Patch(ctx, r.deployment, types.JSONPatchType, patch, metav1.PatchOptions{}); err != nil {
		return nil, fmt.Errorf("failed to set key renew period on %s/%s: %w", r.namespace, r.deployment, err)
	}
	r.logger.WarnContext(ctx, "controller key renewal turned on",
		"event", "renewal.enabled", "deployment", r.namespace+"/"+r.deployment, "period", period.String())
	r.logger.WarnContext(ctx, "controller restarted to apply key renewal",
		"event", "controller.restarted", "deployment", r.namespace+"/"+r.deployment, "reason", "key renewal enabled")
	return renewalResult{Period: period.String()}, nil
}

// controllerContainerIndex finds the controller's container: the one named
// like the chart's, or the only one.
func controllerContainerIndex(d *appsv1.Deployment) (int, error) {
	cs := d.Spec.Template.Spec.Containers
	for i, c := range cs {
		if c.Name == controllerContainer {
			return i, nil
		}
	}
	if len(cs) == 1 {
		return 0, nil
	}
	return 0, fmt.Errorf("failed to find the controller container in %s: expected one named %q", d.Name, controllerContainer)
}

// setFlag returns args with --name set to value, keeping the flag's form
// (--name=value or --name value) when it is present in args, and appending
// it otherwise.
func setFlag(args []string, name, value string) []string {
	out := slices.Clone(args)
	for i, a := range out {
		trimmed := strings.TrimLeft(a, "-")
		if len(trimmed) == len(a) {
			continue
		}
		dashes := a[:len(a)-len(trimmed)]
		if strings.HasPrefix(trimmed, name+"=") {
			out[i] = dashes + name + "=" + value
			return out
		}
		if trimmed == name && i+1 < len(out) {
			out[i+1] = value
			return out
		}
	}
	return append(out, "--"+name+"="+value)
}

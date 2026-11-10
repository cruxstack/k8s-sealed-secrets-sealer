package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
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
func (r *Renewal) Enable(ctx context.Context, cmd protocol.Command) (any, error) {
	var p protocol.RenewalEnablePayload
	if err := strictDecode(cmd.Payload, &p); err != nil {
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
	current := renewPeriodOf(lookupSetting(c, renewPeriodFlags...))
	if current == "" {
		// a flag would override it, but it may be on with another period
		return nil, fmt.Errorf("refusing to change key renewal on %s/%s: its renew period is set where the agent cannot read it", r.namespace, r.deployment)
	}
	if cur, err := time.ParseDuration(current); err == nil && cur > 0 {
		return renewalResult{Period: cur.String(), AlreadyEnabled: true}, nil
	}

	args := setRenewPeriod(c.Args, period.String())
	if v, _ := lastFlag(append(slices.Clone(c.Command), args...), renewPeriodFlags); v != period.String() {
		return nil, fmt.Errorf("failed to set key renew period on %s/%s: the controller's arguments cannot be changed safely", r.namespace, r.deployment)
	}
	path := fmt.Sprintf("/spec/template/spec/containers/%d", i)
	// fail if the container changed since it was read
	ops := []map[string]any{{"op": "test", "path": path + "/name", "value": c.Name}}
	if len(c.Args) > 0 {
		ops = append(ops, map[string]any{"op": "test", "path": path + "/args", "value": c.Args})
	}
	// add replaces the arguments, or adds them to a container that has none
	ops = append(ops, map[string]any{"op": "add", "path": path + "/args", "value": args})
	patch, err := json.Marshal(ops)
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

// setRenewPeriod returns args with the key renew period set to value. It
// changes the last --key-renew-period or --rotate-period in args, keeping
// its form (--name=value or --name value), since the last occurrence wins;
// otherwise it adds the flag, before a "--" that ends the flags. A flag in
// args overrides one in the command, which comes before them, and any
// environment variable.
func setRenewPeriod(args []string, value string) []string {
	out := slices.Clone(args)
	flags, end := parseFlags(out)
	for i := len(flags) - 1; i >= 0; i-- {
		f := flags[i]
		if !slices.Contains(renewPeriodFlags, f.name) {
			continue
		}
		if f.inline {
			out[f.at] = "--key-renew-period=" + value
		} else {
			out[f.at], out[f.at+1] = "--key-renew-period", value
		}
		return out
	}
	return slices.Insert(out, end, "--key-renew-period="+value)
}

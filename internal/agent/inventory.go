package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// keyLabelSelector selects the key Secrets the controller loads.
const keyLabelSelector = "sealedsecrets.bitnami.com/sealed-secrets-key=active"

// Report is what the agent knows about its controller.
type Report struct {
	Controller protocol.Controller
	Keys       []protocol.Key
	// Complete is false when Keys is only the active certificate.
	Complete bool
	// Pending lists keys the agent restored that the controller has not
	// loaded yet. They are not in Keys: the controller cannot decrypt with
	// them until it restarts.
	Pending []string
}

// Inventory reads the sealed-secrets controller's keys and settings.
type Inventory struct {
	certs      CertSource
	kube       kubernetes.Interface
	namespace  string
	name       string
	deployment string
	listKeys   bool
	logger     *slog.Logger
	now        func() time.Time

	mu     sync.Mutex
	last   Report
	lastAt time.Time
}

// InventoryOptions configures an Inventory.
type InventoryOptions struct {
	Certs      CertSource
	Kube       kubernetes.Interface
	Namespace  string
	Name       string
	Deployment string
	// ListKeys reads every key Secret's certificate; it needs the keys
	// capability's RBAC. Without it only the active certificate is known.
	ListKeys bool
	Logger   *slog.Logger
	Now      func() time.Time
}

// NewInventory returns an Inventory. It makes no network calls.
func NewInventory(opts InventoryOptions) *Inventory {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Inventory{
		certs:      opts.Certs,
		kube:       opts.Kube,
		namespace:  opts.Namespace,
		name:       opts.Name,
		deployment: opts.Deployment,
		listKeys:   opts.ListKeys,
		logger:     logger,
		now:        now,
	}
}

// Collect reads the controller's active certificate, its flags and, when
// allowed, its whole key set. When part of that cannot be read it fails,
// rather than report less than the controller holds.
func (inv *Inventory) Collect(ctx context.Context) (Report, error) {
	r, err := inv.collect(ctx)
	if err != nil {
		return Report{}, err
	}
	inv.mu.Lock()
	inv.last, inv.lastAt = r, inv.now()
	inv.mu.Unlock()
	return r, nil
}

func (inv *Inventory) collect(ctx context.Context) (Report, error) {
	activePEM, err := inv.certs.ActiveCert(ctx)
	if err != nil {
		return Report{}, err
	}
	active, err := toProtocolKey(activePEM)
	if err != nil {
		return Report{}, fmt.Errorf("failed to use controller's active certificate: %w", err)
	}

	r := Report{
		Controller: protocol.Controller{
			Namespace:         inv.namespace,
			Name:              inv.name,
			ActiveFingerprint: active.Fingerprint,
		},
		Keys: []protocol.Key{active},
	}
	d, err := inv.controllerDeployment(ctx)
	if err != nil {
		return Report{}, err
	}
	if d != nil {
		s := readSettings(d)
		r.Controller.KeyRenewPeriod, r.Controller.KeyOrderPriority = s.keyRenewPeriod, s.keyOrderPriority
	}

	if !inv.listKeys {
		return r, nil
	}
	list, err := inv.kube.CoreV1().Secrets(inv.namespace).List(ctx, metav1.ListOptions{LabelSelector: keyLabelSelector})
	if err != nil {
		return Report{}, fmt.Errorf("failed to list key secrets in %s: %w", inv.namespace, err)
	}
	if r.Pending, err = inv.pending(ctx, d, list.Items, active.Fingerprint); err != nil {
		return Report{}, err
	}
	all := inv.keySet(ctx, list.Items, r.Pending)
	if !containsKey(all, active.Fingerprint) {
		// the controller seals with a key that is not a labeled key Secret;
		// report it anyway so the key set is never missing the active key
		inv.logger.WarnContext(ctx, "controller's active key has no labeled key secret",
			"event", "controller.active_key_unlabeled", "fingerprint", active.Fingerprint)
		all = append(all, active)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].NotBefore.Before(all[j].NotBefore) })
	r.Keys = all
	r.Complete = true
	return r, nil
}

// controllerDeployment reads the controller's Deployment. It returns nil
// and no error when the agent may not read it or it does not exist, so the
// controller's flags are unknown. Any other failure is an error, so one
// failed read does not report the flags as unknown: the control plane
// could take renewal as off in this cluster and turn it on in another.
func (inv *Inventory) controllerDeployment(ctx context.Context) (*appsv1.Deployment, error) {
	d, err := inv.kube.AppsV1().Deployments(inv.namespace).Get(ctx, inv.deployment, metav1.GetOptions{})
	switch {
	case err == nil:
		return d, nil
	case apierrors.IsForbidden(err):
		inv.logger.DebugContext(ctx, "cannot read controller deployment; its flags are unknown",
			"deployment", inv.namespace+"/"+inv.deployment, "error", err)
		return nil, nil
	case apierrors.IsNotFound(err):
		inv.logger.WarnContext(ctx, "cannot read controller deployment; its flags are unknown",
			"deployment", inv.namespace+"/"+inv.deployment, "error", err)
		return nil, nil
	default:
		return nil, fmt.Errorf("failed to get controller deployment %s/%s: %w", inv.namespace, inv.deployment, err)
	}
}

// pending returns the restored keys among secrets that the controller has
// not loaded. It fails when it cannot tell: when the controller's pods
// cannot be read, or none of them is ready, as while it restarts. Leaving
// the keys out then would report keys it loaded long ago as missing.
func (inv *Inventory) pending(ctx context.Context, d *appsv1.Deployment, secrets []corev1.Secret, active string) ([]string, error) {
	if !slices.ContainsFunc(secrets, restoredByAgent) {
		return nil, nil
	}
	var pods []corev1.Pod
	var readErr error
	if d == nil {
		readErr = fmt.Errorf("cannot read controller deployment %s/%s", inv.namespace, inv.deployment)
	} else {
		pods, readErr = controllerPods(ctx, inv.kube, d)
	}
	st := restoreState(secrets, pods, active)
	switch {
	case len(st.pending) == 0:
		return nil, nil
	case readErr != nil:
		return nil, fmt.Errorf("failed to tell which restored keys the controller has loaded: %w", readErr)
	case st.unsure:
		return nil, errors.New("failed to tell which restored keys the controller has loaded: none of its pods is ready")
	}
	inv.logger.DebugContext(ctx, "restored keys the controller has not loaded yet", "fingerprints", st.fingerprints())
	return st.fingerprints(), nil
}

// keySet reads the certificate of every key Secret, leaving out the keys in
// skip. The private keys come back in the same objects; they are never read
// or kept.
func (inv *Inventory) keySet(ctx context.Context, secrets []corev1.Secret, skip []string) []protocol.Key {
	var out []protocol.Key
	for i := range secrets {
		s := &secrets[i]
		k, err := toProtocolKey(s.Data[corev1.TLSCertKey])
		if err != nil {
			inv.logger.WarnContext(ctx, "skipping unusable key secret",
				"event", "controller.key_unusable", "secret", s.Name, "error", err)
			continue
		}
		if !containsKey(out, k.Fingerprint) && !slices.Contains(skip, k.Fingerprint) {
			out = append(out, k)
		}
	}
	return out
}

// Fallback returns a Collector that reads the controller as Collect does,
// but while the controller cannot be read answers with the last report
// read within maxAge. A controller restarting serves nothing for a few
// seconds, and the keys it loaded before are still the keys it holds; the
// sealer uses it so seals do not fail meanwhile.
func (inv *Inventory) Fallback(maxAge time.Duration) Collector {
	return fallback{inv: inv, maxAge: maxAge}
}

type fallback struct {
	inv    *Inventory
	maxAge time.Duration
}

func (f fallback) Collect(ctx context.Context) (Report, error) {
	r, err := f.inv.Collect(ctx)
	if err == nil {
		return r, nil
	}
	f.inv.mu.Lock()
	last, at := f.inv.last, f.inv.lastAt
	f.inv.mu.Unlock()
	if at.IsZero() || f.inv.now().Sub(at) > f.maxAge {
		return Report{}, err
	}
	f.inv.logger.WarnContext(ctx, "cannot read the controller; using the keys it reported last",
		"event", "controller.read_failed", "error", err, "reported_at", at.UTC().Format(time.RFC3339))
	return last, nil
}

func toProtocolKey(pem []byte) (protocol.Key, error) {
	k, _, err := keys.ParseCert(pem)
	if err != nil {
		return protocol.Key{}, err
	}
	return protocol.Key{
		Fingerprint: k.Fingerprint,
		NotBefore:   k.NotBefore,
		NotAfter:    k.NotAfter,
		Certificate: string(pem),
	}, nil
}

func containsKey(ks []protocol.Key, fp string) bool {
	for _, k := range ks {
		if k.Fingerprint == fp {
			return true
		}
	}
	return false
}

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// keyLabelSelector selects the key Secrets the controller loads.
const keyLabelSelector = "sealedsecrets.bitnami.com/sealed-secrets-key=active"

// Controller defaults, used when its Deployment does not set the flags.
const (
	defaultKeyRenewPeriod   = 30 * 24 * time.Hour
	defaultKeyOrderPriority = "CertNotBefore"
)

// Report is what the agent knows about its controller.
type Report struct {
	Controller protocol.Controller
	Keys       []protocol.Key
	// Complete is false when Keys is only the active certificate.
	Complete bool
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
}

// NewInventory returns an Inventory. It makes no network calls.
func NewInventory(opts InventoryOptions) *Inventory {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Inventory{
		certs:      opts.Certs,
		kube:       opts.Kube,
		namespace:  opts.Namespace,
		name:       opts.Name,
		deployment: opts.Deployment,
		listKeys:   opts.ListKeys,
		logger:     logger,
	}
}

// Collect reads the controller's active certificate, its flags and, when
// allowed, its whole key set.
func (inv *Inventory) Collect(ctx context.Context) (Report, error) {
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
	r.Controller.KeyRenewPeriod, r.Controller.KeyOrderPriority = inv.controllerFlags(ctx)

	if !inv.listKeys {
		return r, nil
	}
	all, err := inv.keySet(ctx)
	if err != nil {
		return Report{}, err
	}
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

// keySet reads the certificate of every key Secret. The private keys come
// back in the same objects; they are never read or kept.
func (inv *Inventory) keySet(ctx context.Context) ([]protocol.Key, error) {
	list, err := inv.kube.CoreV1().Secrets(inv.namespace).List(ctx, metav1.ListOptions{LabelSelector: keyLabelSelector})
	if err != nil {
		return nil, fmt.Errorf("failed to list key secrets in %s: %w", inv.namespace, err)
	}
	var out []protocol.Key
	for i := range list.Items {
		s := &list.Items[i]
		k, err := toProtocolKey(s.Data["tls.crt"])
		if err != nil {
			inv.logger.WarnContext(ctx, "skipping unusable key secret",
				"event", "controller.key_unusable", "secret", s.Name, "error", err)
			continue
		}
		if !containsKey(out, k.Fingerprint) {
			out = append(out, k)
		}
	}
	return out, nil
}

// controllerFlags returns the controller's key renew period and key order,
// with the controller's defaults for flags it does not set. Both are empty
// when the Deployment cannot be read.
func (inv *Inventory) controllerFlags(ctx context.Context) (string, string) {
	d, err := inv.kube.AppsV1().Deployments(inv.namespace).Get(ctx, inv.deployment, metav1.GetOptions{})
	if err != nil {
		level := slog.LevelWarn
		if apierrors.IsForbidden(err) {
			level = slog.LevelDebug
		}
		inv.logger.Log(ctx, level, "cannot read controller deployment; its flags are unknown",
			"deployment", inv.namespace+"/"+inv.deployment, "error", err)
		return "", ""
	}
	renew, order := defaultKeyRenewPeriod.String(), defaultKeyOrderPriority
	for _, c := range d.Spec.Template.Spec.Containers {
		args := append(append([]string{}, c.Command...), c.Args...)
		if v, ok := flagValue(args, "key-renew-period"); ok {
			if p, err := time.ParseDuration(v); err == nil {
				renew = p.String()
			} else if v == "0" {
				renew = time.Duration(0).String()
			}
		}
		if v, ok := flagValue(args, "key-order-priority"); ok {
			order = v
		}
	}
	return renew, order
}

// flagValue finds --name=value or --name value (or a single dash) in args.
func flagValue(args []string, name string) (string, bool) {
	for i, a := range args {
		trimmed := strings.TrimLeft(a, "-")
		if len(trimmed) == len(a) {
			continue
		}
		if v, ok := strings.CutPrefix(trimmed, name+"="); ok {
			return v, true
		}
		if trimmed == name && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
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

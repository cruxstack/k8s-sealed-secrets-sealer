package agent

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"slices"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
)

// The controller reads its key Secrets only when it starts. A key the agent
// restores is therefore in the controller's key set only once a controller
// pod has started after the key's Secret was created. Until then the agent
// leaves the key out of what it reports and seals with, and it restarts the
// controller by deleting the pods that predate the key; their Deployment
// starts new ones. Deleting pods needs no write access to the Deployment,
// which would let the agent change what the controller runs.

// Restart retries, while restored keys stay unloaded because a restart
// failed or never happened.
const (
	restartRetry    = 30 * time.Second
	restartRetryMax = 10 * time.Minute
)

// restoredKey is a key Secret the agent restored.
type restoredKey struct {
	fingerprint string
	secret      string
	created     time.Time
}

// loadState is how far the controller has loaded the keys restored into it.
type loadState struct {
	// pending are restored keys the controller has not loaded.
	pending []restoredKey
	// stale are the controller's pods that started before a pending key's
	// Secret was created and so will never load it.
	stale []corev1.Pod
}

func (s loadState) fingerprints() []string {
	out := make([]string, 0, len(s.pending))
	for _, k := range s.pending {
		out = append(out, k.fingerprint)
	}
	return out
}

// restoreState works out which of the restored keys among secrets (the
// labeled key Secrets) the controller's pods have loaded. A pod has a key
// when the pod was created after the key's Secret. Both times are the API
// server's, in whole seconds, so the pod must be from a later second. A key
// counts as loaded when every ready pod has it, or when the controller seals
// with it (active), so it serves its certificate.
func restoreState(secrets []corev1.Secret, pods []corev1.Pod, active string) loadState {
	var running, ready []corev1.Pod
	for _, p := range pods {
		if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		running = append(running, p)
		if podReady(p) {
			ready = append(ready, p)
		}
	}
	var st loadState
	var newest time.Time
	for i := range secrets {
		s := &secrets[i]
		if !restoredByAgent(*s) {
			continue
		}
		k, _, err := keys.ParseCert(s.Data[corev1.TLSCertKey])
		if err != nil || k.Fingerprint == active {
			continue
		}
		created := s.CreationTimestamp.Time
		predates := func(p corev1.Pod) bool { return !p.CreationTimestamp.After(created) }
		if len(ready) > 0 && !slices.ContainsFunc(ready, predates) {
			continue
		}
		st.pending = append(st.pending, restoredKey{fingerprint: k.Fingerprint, secret: s.Name, created: created})
		if created.After(newest) {
			newest = created
		}
	}
	if len(st.pending) == 0 {
		return st
	}
	for _, p := range running {
		if !p.CreationTimestamp.After(newest) {
			st.stale = append(st.stale, p)
		}
	}
	return st
}

// restoredByAgent reports whether the agent created a key Secret, restoring
// it from escrow.
func restoredByAgent(s corev1.Secret) bool {
	return s.Annotations[annotationRestoredFrom] == escrowedRestoredFromValue
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// controllerPods lists the pods of the controller Deployment d.
func controllerPods(ctx context.Context, kube kubernetes.Interface, d *appsv1.Deployment) ([]corev1.Pod, error) {
	selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, fmt.Errorf("failed to find the pods of controller deployment %s/%s: it has no usable selector", d.Namespace, d.Name)
	}
	list, err := kube.CoreV1().Pods(d.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, fmt.Errorf("failed to list controller pods in %s: %w", d.Namespace, err)
	}
	return list.Items, nil
}

// LoadRestored restarts the controller when pods that predate keys this
// agent restored are still running, which is the case when a restart
// failed or never happened. The check-in loop calls it while restored keys
// are not loaded; active is the key the controller seals with. Attempts
// back off from restartRetry to restartRetryMax.
func (k *KeySync) LoadRestored(ctx context.Context, active string) {
	if _, err := k.restart(ctx, active, "restored keys not loaded", false); err != nil {
		k.logger.ErrorContext(ctx, "failed to restart the controller to load restored keys",
			"event", "controller.restart_failed", "env", k.env, "deployment", k.namespace+"/"+k.deployment, "error", err)
	}
}

// restart deletes the controller pods that predate a restored key, unless
// the last attempt was too recent and force is false. It reports whether it
// deleted any.
func (k *KeySync) restart(ctx context.Context, active, reason string, force bool) (bool, error) {
	k.restartMu.Lock()
	defer k.restartMu.Unlock()
	if !force && k.now().Before(k.nextRestart) {
		return false, nil
	}
	restarted, err := k.restartStale(ctx, active, reason)
	if err == nil && !restarted {
		// nothing to restart: new pods are starting, or all is loaded
		k.restartBackoff = restartRetry
		return false, nil
	}
	k.nextRestart = k.now().Add(k.restartBackoff)
	k.restartBackoff = min(2*k.restartBackoff, restartRetryMax)
	return restarted, err
}

func (k *KeySync) restartStale(ctx context.Context, active, reason string) (bool, error) {
	secrets, err := k.listKeySecrets(ctx, keyLabelSelector)
	if err != nil {
		return false, err
	}
	if !slices.ContainsFunc(secrets, restoredByAgent) {
		return false, nil
	}
	d, err := k.kube.AppsV1().Deployments(k.namespace).Get(ctx, k.deployment, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get controller deployment %s/%s: %w", k.namespace, k.deployment, err)
	}
	pods, err := controllerPods(ctx, k.kube, d)
	if err != nil {
		return false, err
	}
	st := restoreState(secrets, pods, active)
	if len(st.stale) == 0 {
		return false, nil
	}
	// the new pods read every key Secret, and stop if one does not load;
	// the old ones would be gone by then
	for i := range secrets {
		if err := loadable(&secrets[i]); err != nil {
			return false, fmt.Errorf("refusing to restart controller %s/%s: key secret %s would stop it from starting: %w",
				k.namespace, k.deployment, secrets[i].Name, err)
		}
	}
	// the new pods must be created in a later second than the keys
	sleep(ctx, k.settle-time.Since(k.lastCreate))
	var names []string
	for _, p := range st.stale {
		uid := p.UID
		err := k.kube.CoreV1().Pods(k.namespace).Delete(ctx, p.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		if err != nil && !apierrors.IsNotFound(err) {
			return len(names) > 0, fmt.Errorf("failed to restart controller pod %s/%s: %w", k.namespace, p.Name, err)
		}
		names = append(names, p.Name)
	}
	k.logger.WarnContext(ctx, "controller restarted to load restored keys",
		"event", "controller.restarted", "env", k.env, "deployment", k.namespace+"/"+k.deployment,
		"reason", reason, "pods", names, "fingerprints", st.fingerprints())
	return true, nil
}

// loadable checks a key Secret the way the controller reads one when it
// starts (readKey in sealed-secrets v0.41): the first private key in tls.key
// it can parse, which must be RSA, and the certificates in tls.crt.
func loadable(s *corev1.Secret) error {
	_, err := readKeyPair(s.Data[corev1.TLSCertKey], s.Data[corev1.TLSPrivateKeyKey])
	return err
}

// readKeyPair reads a key Secret's data as the controller does and returns
// its private key.
func readKeyPair(certPEM, keyPEM []byte) (*rsa.PrivateKey, error) {
	key, err := keyutil.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, errors.New("private key does not parse")
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	if _, err := cert.ParseCertsPEM(certPEM); err != nil {
		return nil, errors.New("certificate does not parse")
	}
	return priv, nil
}

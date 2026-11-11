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
	"k8s.io/apimachinery/pkg/types"
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
// which would let the agent change what the controller runs. A delete is
// not an eviction, so PodDisruptionBudgets do not hold it back; with
// several replicas the agent deletes one pod at a time instead.

// Restart retries, while restored keys stay unloaded because a restart
// failed or never happened.
const (
	restartRetry    = 30 * time.Second
	restartRetryMax = 10 * time.Minute
)

// Restarts of a controller with several replicas.
const (
	// restartPoll is how often a restart checks whether the pod that
	// replaces the one it deleted is ready.
	restartPoll = 2 * time.Second
	// restartWaitMax bounds the wait for one replacement to become ready.
	restartWaitMax = 2 * time.Minute
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
	// unsure is set when keys are pending only because no controller pod
	// is ready, as while it restarts: which keys it has loaded cannot be
	// told then, and every restored key counts as pending.
	unsure bool
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
		if !podRunning(p) {
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
	st.unsure = len(ready) == 0
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

// podRunning reports whether a pod is running or starting: not terminating
// and not finished.
func podRunning(p corev1.Pod) bool {
	return p.DeletionTimestamp == nil && p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed
}

func podReady(p corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// controllerPods lists the pods of the controller Deployment d: those its
// selector matches whose ReplicaSet d owns. A pod of another workload that
// happens to match the selector is neither counted as the controller's nor
// deleted.
func controllerPods(ctx context.Context, kube kubernetes.Interface, d *appsv1.Deployment) ([]corev1.Pod, error) {
	selector, err := metav1.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil || selector.Empty() {
		return nil, fmt.Errorf("failed to find the pods of controller deployment %s/%s: it has no usable selector", d.Namespace, d.Name)
	}
	opts := metav1.ListOptions{LabelSelector: selector.String()}
	sets, err := kube.AppsV1().ReplicaSets(d.Namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list controller replica sets in %s: %w", d.Namespace, err)
	}
	owned := map[types.UID]bool{}
	for i := range sets.Items {
		if ref := metav1.GetControllerOf(&sets.Items[i]); ref != nil && ref.UID == d.UID {
			owned[sets.Items[i].UID] = true
		}
	}
	list, err := kube.CoreV1().Pods(d.Namespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list controller pods in %s: %w", d.Namespace, err)
	}
	var out []corev1.Pod
	for i := range list.Items {
		if ref := metav1.GetControllerOf(&list.Items[i]); ref != nil && ref.Kind == "ReplicaSet" && owned[ref.UID] {
			out = append(out, list.Items[i])
		}
	}
	return out, nil
}

// LoadRestored restarts the controller when pods that predate keys this
// agent restored, or that were running when it deleted keys, are still
// running, which is the case when a restart failed or never happened. The
// check-in loop calls it while restored keys are not loaded or deleted
// ones may be (DeletedLoaded); active is the key the controller seals
// with. Attempts back off from restartRetry to restartRetryMax. While a
// restore runs it does nothing: the restore's own restart covers the keys,
// and one in between would restart the controller twice.
func (k *KeySync) LoadRestored(ctx context.Context, active string) {
	if k.restoring.Load() > 0 {
		return
	}
	reason := "restored keys not loaded"
	if k.DeletedLoaded() {
		reason = "deleted keys still loaded"
	}
	if _, err := k.restart(ctx, active, reason, false); err != nil {
		k.logger.ErrorContext(ctx, "failed to restart the controller to load restored keys",
			"event", "controller.restart_failed", "env", k.env, "deployment", k.namespace+"/"+k.deployment, "error", err)
	}
}

// DeletedLoaded reports whether controller pods that were running when
// this agent deleted key Secrets may still be: they hold the deleted keys
// until they restart.
func (k *KeySync) DeletedLoaded() bool {
	k.restartMu.Lock()
	defer k.restartMu.Unlock()
	return len(k.dropped) > 0
}

// unloadDeleted restarts the controller after this agent deleted key
// Secrets: every controller pod running now started before, and holds the
// deleted keys until it restarts. It goes through every replica, as a
// restore's restart does; the check-in loop retries one that failed.
func (k *KeySync) unloadDeleted(ctx context.Context) (bool, error) {
	d, err := k.kube.AppsV1().Deployments(k.namespace).Get(ctx, k.deployment, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get controller deployment %s/%s: %w", k.namespace, k.deployment, err)
	}
	pods, err := controllerPods(ctx, k.kube, d)
	if err != nil {
		return false, err
	}
	k.restartMu.Lock()
	for _, p := range pods {
		if podRunning(p) {
			k.dropped[p.UID] = true
		}
	}
	k.restartMu.Unlock()
	return k.restart(ctx, "", "keys deleted", true)
}

// beginRestore marks a restore as running, once any restart in progress
// has ended; endRestore marks it done.
func (k *KeySync) beginRestore() {
	k.restartMu.Lock()
	defer k.restartMu.Unlock()
	k.restoring.Add(1)
}

func (k *KeySync) endRestore() {
	k.restoring.Add(-1)
}

// restart deletes the controller pods that predate a restored key, or that
// were running when this agent deleted keys. It reports whether it deleted
// any. A restore's or removal's restart (force) runs at once and goes
// through every replica, waiting for each replacement. The check-in loop's
// does nothing while a restore runs or the last attempt was too recent,
// and deletes at most one pod while a replacement starts, so the loop is
// not held up.
func (k *KeySync) restart(ctx context.Context, active, reason string, force bool) (bool, error) {
	k.restartMu.Lock()
	defer k.restartMu.Unlock()
	if !force && (k.restoring.Load() > 0 || k.now().Before(k.nextRestart)) {
		return false, nil
	}
	restarted, err := k.restartStale(ctx, active, reason, force)
	if err == nil && !restarted {
		// nothing to restart: new pods are starting, or all is loaded
		k.restartBackoff = restartRetry
		return false, nil
	}
	k.nextRestart = k.now().Add(k.restartBackoff)
	k.restartBackoff = min(2*k.restartBackoff, restartRetryMax)
	return restarted, err
}

// restartStale deletes the controller's pods that predate a restored key,
// or hold a deleted one, one at a time: after each, the next waits until a
// pod that replaces it is ready, so a controller with several replicas
// keeps serving. Without wait it stops there instead, leaving the rest to a
// later attempt. The caller holds restartMu.
func (k *KeySync) restartStale(ctx context.Context, active, reason string, wait bool) (bool, error) {
	secrets, err := k.listKeySecrets(ctx, keyLabelSelector)
	if err != nil {
		return false, err
	}
	if !slices.ContainsFunc(secrets, restoredByAgent) && len(k.dropped) == 0 {
		return false, nil
	}
	d, err := k.kube.AppsV1().Deployments(k.namespace).Get(ctx, k.deployment, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get controller deployment %s/%s: %w", k.namespace, k.deployment, err)
	}
	var deleted, fingerprints []string
	var before map[types.UID]bool
	var waitingSince time.Time
	for {
		pods, err := controllerPods(ctx, k.kube, d)
		if err != nil {
			return len(deleted) > 0, err
		}
		st := restoreState(secrets, pods, active)
		st.stale = k.withDropped(st.stale, pods)
		if len(st.stale) == 0 {
			break
		}
		if (before != nil && !replaced(pods, before)) || starting(pods, st.stale) {
			if !wait {
				break
			}
			if waitingSince.IsZero() {
				waitingSince = time.Now()
			}
			if time.Since(waitingSince) > restartWaitMax {
				return len(deleted) > 0, fmt.Errorf("failed to restart controller %s/%s: no new pod became ready within %s", k.namespace, k.deployment, restartWaitMax)
			}
			sleep(ctx, k.restartPoll)
			if ctx.Err() != nil {
				return len(deleted) > 0, fmt.Errorf("failed to restart controller %s/%s: stopped waiting for a new pod to become ready: %w", k.namespace, k.deployment, ctx.Err())
			}
			continue
		}
		waitingSince = time.Time{}
		if len(deleted) == 0 {
			// the new pods read every key Secret, and stop if one does not
			// load; the old ones would be gone by then
			for i := range secrets {
				if err := loadable(&secrets[i]); err != nil {
					return false, fmt.Errorf("refusing to restart controller %s/%s: key secret %s would stop it from starting: %w",
						k.namespace, k.deployment, secrets[i].Name, err)
				}
			}
			// the new pods must be created in a later second than the keys
			sleep(ctx, k.settle-time.Since(k.lastCreate))
			fingerprints = st.fingerprints()
		}
		p := st.stale[0]
		if slices.Contains(deleted, p.Name) {
			return true, fmt.Errorf("failed to restart controller pod %s/%s: still running after it was deleted", k.namespace, p.Name)
		}
		before = podUIDs(pods)
		uid := p.UID
		err = k.kube.CoreV1().Pods(k.namespace).Delete(ctx, p.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}})
		if err != nil && !apierrors.IsNotFound(err) {
			return len(deleted) > 0, fmt.Errorf("failed to restart controller pod %s/%s: %w", k.namespace, p.Name, err)
		}
		deleted = append(deleted, p.Name)
	}
	if len(deleted) == 0 {
		return false, nil
	}
	k.logger.WarnContext(ctx, "controller restarted to load its keys",
		"event", "controller.restarted", "env", k.env, "deployment", k.namespace+"/"+k.deployment,
		"reason", reason, "pods", deleted, "fingerprints", fingerprints)
	return true, nil
}

// withDropped adds to stale the running pods that hold deleted keys, and
// forgets those no longer running. The caller holds restartMu.
func (k *KeySync) withDropped(stale, pods []corev1.Pod) []corev1.Pod {
	running := map[types.UID]bool{}
	for _, p := range pods {
		if !podRunning(p) {
			continue
		}
		running[p.UID] = true
		if k.dropped[p.UID] && !slices.ContainsFunc(stale, func(s corev1.Pod) bool { return s.UID == p.UID }) {
			stale = append(stale, p)
		}
	}
	for uid := range k.dropped {
		if !running[uid] {
			delete(k.dropped, uid)
		}
	}
	return stale
}

// starting reports whether a controller pod other than the stale ones is
// running but not ready yet: a new pod starting.
func starting(pods, stale []corev1.Pod) bool {
	return slices.ContainsFunc(pods, func(p corev1.Pod) bool {
		return podRunning(p) && !podReady(p) &&
			!slices.ContainsFunc(stale, func(s corev1.Pod) bool { return s.UID == p.UID })
	})
}

// replaced reports whether a ready pod has started that is not among
// before.
func replaced(pods []corev1.Pod, before map[types.UID]bool) bool {
	return slices.ContainsFunc(pods, func(p corev1.Pod) bool {
		return podRunning(p) && podReady(p) && !before[p.UID]
	})
}

func podUIDs(pods []corev1.Pod) map[types.UID]bool {
	out := make(map[types.UID]bool, len(pods))
	for _, p := range pods {
		out[p.UID] = true
	}
	return out
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

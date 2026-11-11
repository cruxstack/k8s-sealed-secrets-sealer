package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
)

const ns = "sealed-secrets"

type staticCerts struct {
	pem []byte
	err error
}

func (s staticCerts) ActiveCert(context.Context) ([]byte, error) { return s.pem, s.err }

func keySecret(name string, cert []byte, labeled bool) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"tls.crt": cert, "tls.key": []byte("private")},
	}
	if labeled {
		s.Labels = map[string]string{"sealedsecrets.bitnami.com/sealed-secrets-key": "active"}
	}
	return s
}

// controllerLabels select the controller's pods.
var controllerLabels = map[string]string{"app.kubernetes.io/name": "sealed-secrets"}

// The controller's Deployment and its ReplicaSet; controllerPod makes pods
// of that ReplicaSet.
const (
	deploymentUID = types.UID("deployment")
	replicaSetUID = types.UID("replicaset")
)

func controllerDeployment(args ...string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "sealed-secrets-controller", Namespace: ns, UID: deploymentUID},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: controllerLabels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: controllerLabels},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "controller", Command: []string{"controller"}, Args: args}},
				},
			},
		},
	}
}

// controllerReplicaSet is the ReplicaSet of the controller's Deployment.
func controllerReplicaSet() *appsv1.ReplicaSet {
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sealed-secrets-controller-abc", Namespace: ns, UID: replicaSetUID, Labels: controllerLabels,
			OwnerReferences: []metav1.OwnerReference{ownerRef("Deployment", "sealed-secrets-controller", deploymentUID)},
		},
	}
}

func ownerRef(kind, name string, uid types.UID) metav1.OwnerReference {
	return metav1.OwnerReference{Kind: kind, Name: name, UID: uid, Controller: new(true)}
}

// controllerPod is a running controller pod created at created.
func controllerPod(name string, created time.Time, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: ns, Labels: controllerLabels,
			UID: types.UID(name), CreationTimestamp: metav1.NewTime(created),
			OwnerReferences: []metav1.OwnerReference{ownerRef("ReplicaSet", "sealed-secrets-controller-abc", replicaSetUID)},
		},
		Status: corev1.PodStatus{
			Phase:      corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}},
		},
	}
}

// restoredSecret is a key Secret the agent restored at created.
func restoredSecret(name string, cert []byte, created time.Time) *corev1.Secret {
	s := keySecret(name, cert, true)
	s.CreationTimestamp = metav1.NewTime(created)
	s.Annotations = map[string]string{annotationRestoredFrom: escrowedRestoredFromValue}
	return s
}

func inventory(certs CertSource, listKeys bool, objs ...runtime.Object) *Inventory {
	return NewInventory(InventoryOptions{
		Certs:      certs,
		Kube:       fake.NewClientset(append(objs, controllerReplicaSet())...),
		Namespace:  ns,
		Name:       "sealed-secrets-controller",
		Deployment: "sealed-secrets-controller",
		ListKeys:   listKeys,
	})
}

func TestInventory_FullKeySet(t *testing.T) {
	old := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now().Add(-60*24*time.Hour))
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now().Add(-time.Hour))
	inv := inventory(staticCerts{pem: active}, true,
		keySecret("sealed-secrets-key2", active, true),
		keySecret("sealed-secrets-key1", old, true),
		keySecret("unrelated", []byte("x"), false),
		controllerDeployment("--update-status", "--key-renew-period", "0", "--key-order-priority=SecretCreationTimestamp"),
	)
	r, err := inv.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.Complete || len(r.Keys) != 2 {
		t.Fatalf("report = %+v", r)
	}
	if !r.Keys[0].NotBefore.Before(r.Keys[1].NotBefore) || r.Keys[1].Fingerprint != r.Controller.ActiveFingerprint {
		t.Errorf("keys not ordered oldest first with the active key last: %+v", r.Keys)
	}
	if r.Controller.KeyRenewPeriod != "0s" || r.Controller.KeyOrderPriority != "SecretCreationTimestamp" {
		t.Errorf("flags = %q / %q", r.Controller.KeyRenewPeriod, r.Controller.KeyOrderPriority)
	}
	for _, k := range r.Keys {
		if strings.Contains(k.Certificate, "private") {
			t.Fatal("a private key reached the report")
		}
	}
}

func TestInventory_ActiveOnlyWithoutKeysCapability(t *testing.T) {
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now().Add(-time.Hour))
	inv := inventory(staticCerts{pem: active}, false, controllerDeployment("--update-status"))
	r, err := inv.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete || len(r.Keys) != 1 || r.Keys[0].Fingerprint != r.Controller.ActiveFingerprint {
		t.Fatalf("report = %+v", r)
	}
	// controller defaults apply when the flags are absent
	if r.Controller.KeyRenewPeriod != "720h0m0s" || r.Controller.KeyOrderPriority != "CertNotBefore" {
		t.Errorf("flags = %q / %q", r.Controller.KeyRenewPeriod, r.Controller.KeyOrderPriority)
	}
}

// The controller also takes its settings from SEALED_SECRETS_ variables.
func TestInventory_SettingsFromVariables(t *testing.T) {
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now())
	d := controllerDeployment("--update-status")
	d.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{
		{Name: "SEALED_SECRETS_KEY_ORDER_PRIORITY", Value: "SecretCreationTimestamp"},
		{Name: "SEALED_SECRETS_ROTATE_PERIOD", Value: "0"},
	}
	r, err := inventory(staticCerts{pem: active}, false, d).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Controller.KeyRenewPeriod != "0s" || r.Controller.KeyOrderPriority != "SecretCreationTimestamp" {
		t.Errorf("flags = %q / %q", r.Controller.KeyRenewPeriod, r.Controller.KeyOrderPriority)
	}
}

func TestInventory_UnknownFlagsWhenDeploymentForbidden(t *testing.T) {
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now())
	inv := inventory(staticCerts{pem: active}, false)
	inv.kube.(*fake.Clientset).PrependReactor("get", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "deployments"}, "sealed-secrets-controller", errors.New("rbac"))
	})
	r, err := inv.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Controller.KeyRenewPeriod != "" || r.Controller.KeyOrderPriority != "" {
		t.Errorf("flags should be unknown: %+v", r.Controller)
	}
}

func TestInventory_ActiveKeyWithoutSecretIsStillReported(t *testing.T) {
	old := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now().Add(-48*time.Hour))
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now())
	inv := inventory(staticCerts{pem: active}, true, keySecret("k1", old, true), controllerDeployment())
	r, err := inv.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Keys) != 2 || !containsKey(r.Keys, r.Controller.ActiveFingerprint) {
		t.Fatalf("keys = %+v", r.Keys)
	}
}

func TestInventory_FailsWithoutActiveCert(t *testing.T) {
	inv := inventory(staticCerts{err: errors.New("proxy down")}, true)
	if _, err := inv.Collect(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
}

// A key the agent restored is held only once a controller pod started after
// it; until then it is left out of the report and listed as pending.
func TestInventory_LeavesOutRestoredKeysNotLoaded(t *testing.T) {
	now := time.Now()
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), now.Add(-48*time.Hour))
	restored := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), now.Add(-time.Hour))
	restoredKey, _ := toProtocolKey(restored)
	objs := []runtime.Object{
		keySecret("own", active, true),
		restoredSecret("restored", restored, now.Add(-time.Minute)),
		controllerDeployment(),
	}

	inv := inventory(staticCerts{pem: active}, true, append(objs, controllerPod("old", now.Add(-time.Hour), true))...)
	r, err := inv.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if containsKey(r.Keys, restoredKey.Fingerprint) || len(r.Keys) != 1 || len(r.Pending) != 1 || r.Pending[0] != restoredKey.Fingerprint {
		t.Fatalf("keys = %d, pending = %v", len(r.Keys), r.Pending)
	}

	inv = inventory(staticCerts{pem: active}, true, append(objs, controllerPod("new", now, true))...)
	if r, err = inv.Collect(context.Background()); err != nil || !containsKey(r.Keys, restoredKey.Fingerprint) || len(r.Pending) != 0 {
		t.Fatalf("after a restart: err = %v, keys = %d, pending = %v", err, len(r.Keys), r.Pending)
	}

	// a new pod of another workload that the selector matches is not the
	// controller's, so it proves nothing
	other := controllerPod("other", now, true)
	other.OwnerReferences = []metav1.OwnerReference{ownerRef("ReplicaSet", "other", "other-replicaset")}
	inv = inventory(staticCerts{pem: active}, true, append(objs, other)...)
	if r, err = inv.Collect(context.Background()); err == nil && containsKey(r.Keys, restoredKey.Fingerprint) {
		t.Fatal("another workload's pod counted as the controller having loaded the key")
	}
}

// A restored key the controller loaded long ago stays in the report when
// its pods cannot be told apart for a moment: Collect fails instead of
// reporting it missing, and the sealer keeps the last report.
func TestInventory_FailsRatherThanLeaveOutLoadedKeys(t *testing.T) {
	now := time.Now()
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), now.Add(-time.Hour))
	old := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), now.Add(-48*time.Hour))
	oldKey, _ := toProtocolKey(old)
	transient := errors.New("etcdserver: request timed out")
	fail := func(verb, resource string, err error) func(*fake.Clientset) {
		return func(kube *fake.Clientset) {
			kube.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, err
			})
		}
	}
	cases := map[string]func(*fake.Clientset){
		"pods unreadable":        fail("list", "pods", transient),
		"replica sets forbidden": fail("list", "replicasets", apierrors.NewForbidden(schema.GroupResource{Group: "apps", Resource: "replicasets"}, "", errors.New("rbac"))),
		"deployment unreadable":  fail("get", "deployments", transient),
		// the restart window: the old pod is terminating and the new one
		// is not ready yet
		"no pod ready": func(kube *fake.Clientset) {
			ctx := context.Background()
			pod, err := kube.CoreV1().Pods(ns).Get(ctx, "pod", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			pod.DeletionTimestamp = &metav1.Time{Time: now}
			if _, err := kube.CoreV1().Pods(ns).Update(ctx, pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := kube.CoreV1().Pods(ns).Create(ctx, controllerPod("new", now.Add(time.Second), false), metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			kube := fake.NewClientset(
				keySecret("own", active, true),
				restoredSecret("restored", old, now.Add(-24*time.Hour)),
				controllerDeployment("--update-status"),
				controllerReplicaSet(),
				// created after the restored key's Secret: it loaded it
				controllerPod("pod", now.Add(-time.Hour), true),
			)
			inv := NewInventory(InventoryOptions{
				Certs: staticCerts{pem: active}, Kube: kube, Namespace: ns,
				Name: "sealed-secrets-controller", Deployment: "sealed-secrets-controller", ListKeys: true,
			})
			r, err := inv.Collect(context.Background())
			if err != nil || len(r.Keys) != 2 || len(r.Pending) != 0 {
				t.Fatalf("healthy read: err = %v, keys = %d, pending = %v", err, len(r.Keys), r.Pending)
			}
			breakIt(kube)
			if r, err := inv.Collect(context.Background()); err == nil {
				t.Fatalf("reported %d keys and pending %v instead of failing", len(r.Keys), r.Pending)
			}
			if r, err := inv.Fallback(time.Minute).Collect(context.Background()); err != nil || !containsKey(r.Keys, oldKey.Fingerprint) {
				t.Fatalf("fallback: err = %v, keys = %d", err, len(r.Keys))
			}
		})
	}
}

// A Deployment that may not be read, or is not there, leaves the flags
// unknown; one read that fails otherwise fails the report, rather than
// report them unknown for one check-in.
func TestInventory_DeploymentReadErrors(t *testing.T) {
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), time.Now())
	cases := map[string]struct {
		err  error
		fail bool
	}{
		"not found": {err: apierrors.NewNotFound(schema.GroupResource{Group: "apps", Resource: "deployments"}, "sealed-secrets-controller")},
		"transient": {err: errors.New("etcdserver: request timed out"), fail: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			inv := inventory(staticCerts{pem: active}, false, controllerDeployment())
			inv.kube.(*fake.Clientset).PrependReactor("get", "deployments", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			r, err := inv.Collect(context.Background())
			if (err != nil) != tc.fail {
				t.Fatalf("err = %v, want failure %v", err, tc.fail)
			}
			if err == nil && (r.Controller.KeyRenewPeriod != "" || r.Controller.KeyOrderPriority != "") {
				t.Errorf("flags should be unknown: %+v", r.Controller)
			}
		})
	}
}

// While the controller restarts it serves nothing; the sealer seals with
// the keys it reported last, for a while.
func TestInventory_FallbackWhileControllerUnreachable(t *testing.T) {
	now := time.Now()
	active := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), now.Add(-time.Hour))
	certs := &switchableCerts{pem: active}
	inv := NewInventory(InventoryOptions{
		Certs: certs, Kube: fake.NewClientset(controllerDeployment()), Namespace: ns,
		Name: "sealed-secrets-controller", Deployment: "sealed-secrets-controller",
		Now: func() time.Time { return now },
	})
	keys := inv.Fallback(time.Minute)
	if _, err := keys.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	certs.err = errors.New("no endpoints available")
	if r, err := keys.Collect(context.Background()); err != nil || len(r.Keys) != 1 {
		t.Fatalf("within the window: err = %v, keys = %d", err, len(r.Keys))
	}
	if _, err := inv.Collect(context.Background()); err == nil {
		t.Fatal("Collect itself must not fall back: check-ins report what is there")
	}
	now = now.Add(2 * time.Minute)
	if _, err := keys.Collect(context.Background()); err == nil {
		t.Fatal("fell back to a report older than the window")
	}
}

type switchableCerts struct {
	pem []byte
	err error
}

func (s *switchableCerts) ActiveCert(context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.pem, nil
}

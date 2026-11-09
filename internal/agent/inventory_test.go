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

func controllerDeployment(args ...string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "sealed-secrets-controller", Namespace: ns},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "controller", Command: []string{"controller"}, Args: args}},
		}}},
	}
}

func inventory(certs CertSource, listKeys bool, objs ...runtime.Object) *Inventory {
	return NewInventory(InventoryOptions{
		Certs:      certs,
		Kube:       fake.NewClientset(objs...),
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

func TestFlagValue(t *testing.T) {
	args := []string{"controller", "--update-status", "--key-renew-period", "24h", "-key-order-priority=CertNotBefore", "--key-prefix"}
	if v, ok := flagValue(args, "key-renew-period"); !ok || v != "24h" {
		t.Errorf("key-renew-period = %q %v", v, ok)
	}
	if v, ok := flagValue(args, "key-order-priority"); !ok || v != "CertNotBefore" {
		t.Errorf("key-order-priority = %q %v", v, ok)
	}
	if _, ok := flagValue(args, "key-prefix"); ok {
		t.Error("a trailing flag without a value was found")
	}
	if _, ok := flagValue(args, "missing"); ok {
		t.Error("missing flag found")
	}
}

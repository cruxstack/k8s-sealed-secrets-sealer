package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

func TestRenewal_Enable(t *testing.T) {
	cases := map[string]struct {
		args     []string
		env      []corev1.EnvVar
		wantArgs []string
		already  bool
	}{
		"separate value": {
			args:     []string{"--update-status", "--key-renew-period", "0", "--key-prefix", "k"},
			wantArgs: []string{"--update-status", "--key-renew-period", "720h0m0s", "--key-prefix", "k"},
		},
		"equals form": {
			args:     []string{"--key-renew-period=0s"},
			wantArgs: []string{"--key-renew-period=720h0m0s"},
		},
		"already on": {
			args:     []string{"--key-renew-period=168h"},
			wantArgs: []string{"--key-renew-period=168h"},
			already:  true,
		},
		"default is on": {
			args:     []string{"--update-status"},
			wantArgs: []string{"--update-status"},
			already:  true,
		},
		// the last occurrence is what the controller uses
		"off by a later occurrence": {
			args:     []string{"--key-renew-period=168h", "--key-renew-period", "0"},
			wantArgs: []string{"--key-renew-period=168h", "--key-renew-period", "720h0m0s"},
		},
		"off by the old flag name": {
			args:     []string{"--key-renew-period=168h", "--rotate-period=0"},
			wantArgs: []string{"--key-renew-period=168h", "--key-renew-period=720h0m0s"},
		},
		"on by the old flag name": {
			args:     []string{"--rotate-period=24h"},
			wantArgs: []string{"--rotate-period=24h"},
			already:  true,
		},
		// a flag overrides the variable
		"off by a variable": {
			args:     []string{"--update-status", "--", "extra"},
			env:      []corev1.EnvVar{{Name: "SEALED_SECRETS_KEY_RENEW_PERIOD", Value: "0"}},
			wantArgs: []string{"--update-status", "--key-renew-period=720h0m0s", "--", "extra"},
		},
		"on by a variable": {
			env:     []corev1.EnvVar{{Name: "SEALED_SECRETS_KEY_RENEW_PERIOD", Value: "24h"}},
			already: true,
		},
		"no arguments yet": {
			env:      []corev1.EnvVar{{Name: "SEALED_SECRETS_KEY_RENEW_PERIOD", Value: "0"}},
			wantArgs: []string{"--key-renew-period=720h0m0s"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := controllerDeployment(tc.args...)
			d.Spec.Template.Spec.Containers[0].Env = tc.env
			kube := fake.NewClientset(d)
			r := NewRenewal(kube, ns, "sealed-secrets-controller", nil)
			out, err := r.Enable(context.Background(), protocol.Command{Payload: json.RawMessage(`{"period":"720h0m0s"}`)})
			if err != nil {
				t.Fatal(err)
			}
			if res := out.(renewalResult); res.AlreadyEnabled != tc.already {
				t.Errorf("result = %+v", res)
			}
			got, _ := kube.AppsV1().Deployments(ns).Get(context.Background(), "sealed-secrets-controller", metav1.GetOptions{})
			if args := got.Spec.Template.Spec.Containers[0].Args; !slices.Equal(args, tc.wantArgs) {
				t.Errorf("args = %v, want %v", args, tc.wantArgs)
			}
		})
	}
}

func TestRenewal_RejectsBadPeriods(t *testing.T) {
	r := NewRenewal(fake.NewClientset(controllerDeployment("--key-renew-period=0")), ns, "sealed-secrets-controller", nil)
	for _, raw := range []string{`{"period":"1m"}`, `{"period":"10000h"}`, `{"period":"soon"}`, `{"period":"720h","x":1}`} {
		if _, err := r.Enable(context.Background(), protocol.Command{Payload: json.RawMessage(raw)}); err == nil || !strings.Contains(err.Error(), "invalid payload") {
			t.Errorf("%s: err = %v", raw, err)
		}
	}
}

// A period set where the agent cannot read it may be on with another
// period, so the agent changes nothing.
func TestRenewal_RefusesUnknownPeriod(t *testing.T) {
	d := controllerDeployment("--update-status")
	d.Spec.Template.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}}
	kube := fake.NewClientset(d)
	r := NewRenewal(kube, ns, "sealed-secrets-controller", nil)
	if _, err := r.Enable(context.Background(), protocol.Command{Payload: json.RawMessage(`{"period":"720h0m0s"}`)}); err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("err = %v", err)
	}
	got, _ := kube.AppsV1().Deployments(ns).Get(context.Background(), "sealed-secrets-controller", metav1.GetOptions{})
	if args := got.Spec.Template.Spec.Containers[0].Args; !slices.Equal(args, []string{"--update-status"}) {
		t.Fatalf("args changed to %v", args)
	}
}

func TestSetRenewPeriod(t *testing.T) {
	if got := setRenewPeriod([]string{"-key-renew-period=0"}, "1h"); !slices.Equal(got, []string{"-key-renew-period=0", "--key-renew-period=1h"}) {
		t.Errorf("single dash is not a long flag: %v", got)
	}
	if got := setRenewPeriod(nil, "1h"); !slices.Equal(got, []string{"--key-renew-period=1h"}) {
		t.Errorf("absent: %v", got)
	}
}

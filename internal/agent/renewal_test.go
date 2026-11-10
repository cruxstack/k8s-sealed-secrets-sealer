package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestRenewal_Enable(t *testing.T) {
	cases := map[string]struct {
		args     []string
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
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			kube := fake.NewClientset(controllerDeployment(tc.args...))
			r := NewRenewal(kube, ns, "sealed-secrets-controller", nil)
			out, err := r.Enable(context.Background(), json.RawMessage(`{"period":"720h0m0s"}`))
			if err != nil {
				t.Fatal(err)
			}
			if res := out.(renewalResult); res.AlreadyEnabled != tc.already {
				t.Errorf("result = %+v", res)
			}
			d, _ := kube.AppsV1().Deployments(ns).Get(context.Background(), "sealed-secrets-controller", metav1.GetOptions{})
			if got := d.Spec.Template.Spec.Containers[0].Args; !slices.Equal(got, tc.wantArgs) {
				t.Errorf("args = %v, want %v", got, tc.wantArgs)
			}
		})
	}
}

func TestRenewal_RejectsBadPeriods(t *testing.T) {
	r := NewRenewal(fake.NewClientset(controllerDeployment("--key-renew-period=0")), ns, "sealed-secrets-controller", nil)
	for _, raw := range []string{`{"period":"1m"}`, `{"period":"10000h"}`, `{"period":"soon"}`, `{"period":"720h","x":1}`} {
		if _, err := r.Enable(context.Background(), json.RawMessage(raw)); err == nil || !strings.Contains(err.Error(), "invalid payload") {
			t.Errorf("%s: err = %v", raw, err)
		}
	}
}

func TestSetFlag(t *testing.T) {
	if got := setFlag([]string{"-key-renew-period=0"}, "key-renew-period", "1h"); !slices.Equal(got, []string{"-key-renew-period=1h"}) {
		t.Errorf("single dash: %v", got)
	}
	if got := setFlag(nil, "key-renew-period", "1h"); !slices.Equal(got, []string{"--key-renew-period=1h"}) {
		t.Errorf("absent: %v", got)
	}
}

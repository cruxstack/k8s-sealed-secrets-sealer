package agent

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	restclient "k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

// proxyResponse is a canned services/proxy response.
type proxyResponse struct{ body []byte }

func (p proxyResponse) DoRaw(context.Context) ([]byte, error) { return p.body, nil }

func (p proxyResponse) Stream(context.Context) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(p.body)), nil
}

func controllerService(ports ...string) *corev1.Service {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "sealed-secrets-controller", Namespace: "sealed-secrets"}}
	for _, p := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Name: p, Port: 8080})
	}
	return svc
}

// fakeClient serves svc and answers proxy requests with body, recording the
// proxied service name ("scheme:name:port") and path.
func fakeClient(svc runtime.Object, body []byte, proxied *[]string) *fake.Clientset {
	c := fake.NewClientset(svc)
	c.AddProxyReactor("services", func(action k8stesting.Action) (bool, restclient.ResponseWrapper, error) {
		pa := action.(k8stesting.ProxyGetAction)
		*proxied = append(*proxied, pa.GetScheme()+":"+pa.GetName()+":"+pa.GetPort()+pa.GetPath())
		return true, proxyResponse{body: body}, nil
	})
	return c
}

func TestControllerCertSource_PrefersHTTPPort(t *testing.T) {
	var proxied []string
	c := fakeClient(controllerService("metrics", "http"), []byte("PEM"), &proxied)
	src := newControllerCertSource(c.CoreV1(), "sealed-secrets", "sealed-secrets-controller")

	got, err := src.ActiveCert(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "PEM" {
		t.Errorf("body = %q", got)
	}
	want := "http:sealed-secrets-controller:http/v1/cert.pem"
	if len(proxied) != 1 || proxied[0] != want {
		t.Errorf("proxied %v, want [%s]", proxied, want)
	}
}

func TestControllerCertSource_Errors(t *testing.T) {
	cases := map[string]struct {
		svc  runtime.Object
		body []byte
		want string
	}{
		"missing service": {&corev1.Service{}, nil, "failed to get controller service"},
		"no ports":        {controllerService(), nil, "it has no ports"},
		"oversized body":  {controllerService("http"), bytes.Repeat([]byte("a"), maxCertBytes+1), "exceeds"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var proxied []string
			c := fakeClient(tc.svc, tc.body, &proxied)
			src := newControllerCertSource(c.CoreV1(), "sealed-secrets", "sealed-secrets-controller")
			_, err := src.ActiveCert(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

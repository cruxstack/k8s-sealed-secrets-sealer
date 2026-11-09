package agent

import (
	"context"
	"fmt"
	"io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// maxCertBytes bounds the controller's response. A PEM certificate is a few
// KB, so anything larger is a misbehaving endpoint.
const maxCertBytes = 1 << 20

// CertSource returns the PEM certificate the sealed-secrets controller
// currently seals with.
type CertSource interface {
	ActiveCert(ctx context.Context) ([]byte, error)
}

// ControllerCertSource reads the controller's certificate from its
// /v1/cert.pem endpoint through the Kubernetes API service proxy. It needs
// only get on the controller's Service and services/proxy.
type ControllerCertSource struct {
	services  corev1client.ServicesGetter
	namespace string
	name      string
}

// NewControllerCertSource returns a CertSource for the controller Service
// namespace/name. It makes no network calls.
func NewControllerCertSource(cfg *rest.Config, namespace, name string) (*ControllerCertSource, error) {
	c := rest.CopyConfig(cfg)
	// the controller serves the certificate as application/x-pem-file
	c.AcceptContentTypes = "application/x-pem-file, */*"
	client, err := corev1client.NewForConfig(c)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	return newControllerCertSource(client, namespace, name), nil
}

func newControllerCertSource(services corev1client.ServicesGetter, namespace, name string) *ControllerCertSource {
	return &ControllerCertSource{services: services, namespace: namespace, name: name}
}

// ActiveCert returns the controller's current certificate.
func (s *ControllerCertSource) ActiveCert(ctx context.Context) ([]byte, error) {
	svc, err := s.services.Services(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get controller service %s/%s: %w", s.namespace, s.name, err)
	}
	if len(svc.Spec.Ports) == 0 {
		return nil, fmt.Errorf("failed to read controller service %s/%s: it has no ports", s.namespace, s.name)
	}
	// the chart names the API port "http"; fall back to the first port
	port := svc.Spec.Ports[0].Name
	for _, p := range svc.Spec.Ports {
		if p.Name == "http" {
			port = p.Name
			break
		}
	}

	stream, err := s.services.Services(s.namespace).
		ProxyGet("http", s.name, port, "/v1/cert.pem", nil).
		Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificate from controller %s/%s: %w", s.namespace, s.name, err)
	}
	defer func() { _ = stream.Close() }()

	data, err := io.ReadAll(io.LimitReader(stream, maxCertBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate from controller %s/%s: %w", s.namespace, s.name, err)
	}
	if len(data) > maxCertBytes {
		return nil, fmt.Errorf("failed to read certificate from controller %s/%s: response exceeds %d bytes", s.namespace, s.name, maxCertBytes)
	}
	return data, nil
}

package agent

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// RESTConfig returns the Kubernetes client configuration. A named kubeconfig
// context wins; otherwise the in-cluster configuration is used, falling back
// to the kubeconfig's current context for runs outside a cluster.
func RESTConfig(kubeContext string) (*rest.Config, error) {
	if kubeContext == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{CurrentContext: kubeContext}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig (context %q): %w", kubeContext, err)
	}
	return cfg, nil
}

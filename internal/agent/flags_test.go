package agent

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// The agent must read the controller's settings as the controller does
// (sealed-secrets v0.41: pflag, then SEALED_SECRETS_ variables for flags
// not on the command line).
func TestReadSettings(t *testing.T) {
	env := func(kv ...string) []corev1.EnvVar {
		var out []corev1.EnvVar
		for i := 0; i < len(kv); i += 2 {
			out = append(out, corev1.EnvVar{Name: kv[i], Value: kv[i+1]})
		}
		return out
	}
	fromConfigMap := []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}}
	cases := map[string]struct {
		command, args []string
		env           []corev1.EnvVar
		envFrom       []corev1.EnvFromSource
		renew, order  string
		prefix        string
	}{
		"defaults": {
			renew: "720h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"separate and inline values": {
			args:  []string{"--update-status", "--key-renew-period", "24h", "--key-order-priority=SecretCreationTimestamp", "--key-prefix", "k-"},
			renew: "24h0m0s", order: "SecretCreationTimestamp", prefix: "k-",
		},
		"the last occurrence wins": {
			args:  []string{"--key-renew-period=0", "--key-order-priority=SecretCreationTimestamp", "--key-renew-period", "168h", "--key-order-priority", "CertNotBefore"},
			renew: "168h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"a flag in the command comes before the arguments": {
			command: []string{"controller", "--key-renew-period=0"}, args: []string{"--key-renew-period=1h"},
			renew: "1h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"rotate-period is the old name of key-renew-period": {
			args:  []string{"--key-renew-period=720h", "--rotate-period=0"},
			renew: "0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"variables when no flag is set": {
			env:   env("SEALED_SECRETS_KEY_RENEW_PERIOD", "0", "SEALED_SECRETS_KEY_ORDER_PRIORITY", "SecretCreationTimestamp", "SEALED_SECRETS_KEY_PREFIX", "env-"),
			renew: "0s", order: "SecretCreationTimestamp", prefix: "env-",
		},
		"a flag overrides its variable": {
			args:  []string{"--key-order-priority=CertNotBefore"},
			env:   env("SEALED_SECRETS_KEY_ORDER_PRIORITY", "SecretCreationTimestamp", "SEALED_SECRETS_KEY_RENEW_PERIOD", "0"),
			renew: "0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"the last duplicate variable wins": {
			env:   env("SEALED_SECRETS_KEY_RENEW_PERIOD", "0", "SEALED_SECRETS_KEY_RENEW_PERIOD", "48h"),
			renew: "48h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"the old name's variable sorts last and wins": {
			env:   env("SEALED_SECRETS_ROTATE_PERIOD", "0", "SEALED_SECRETS_KEY_RENEW_PERIOD", "48h"),
			renew: "0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"a variable the controller cannot parse turns renewal off": {
			env:   env("SEALED_SECRETS_KEY_RENEW_PERIOD", "monthly"),
			renew: "0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"an order other than SecretCreationTimestamp is NotBefore": {
			args:  []string{"--key-order-priority=secretcreationtimestamp"},
			renew: "720h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"envFrom may set anything": {
			envFrom: fromConfigMap,
			renew:   "", order: "", prefix: "sealed-secrets-key",
		},
		"envFrom with another prefix sets nothing here": {
			envFrom: []corev1.EnvFromSource{{Prefix: "OTHER_", ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "x"}}}},
			renew:   "720h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"a flag is known even with envFrom": {
			args: []string{"--key-renew-period=0", "--key-order-priority=CertNotBefore"}, envFrom: fromConfigMap,
			renew: "0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"variables from valueFrom or referring to others are unknown": {
			env: []corev1.EnvVar{
				{Name: "SEALED_SECRETS_KEY_RENEW_PERIOD", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Key: "period"}}},
				{Name: "SEALED_SECRETS_KEY_ORDER_PRIORITY", Value: "$(ORDER)"},
			},
			renew: "", order: "", prefix: "sealed-secrets-key",
		},
		"flags referring to variables are unknown": {
			args:  []string{"--key-renew-period", "$(PERIOD)", "--key-order-priority=$(ORDER)"},
			renew: "", order: "", prefix: "sealed-secrets-key",
		},
		"nothing after -- is a flag, and single dashes are not long flags": {
			args:  []string{"-key-renew-period=0", "--", "--key-order-priority=SecretCreationTimestamp"},
			renew: "720h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
		"boolean flags take no separate value": {
			args:  []string{"--update-status", "--key-renew-period", "0", "--all-namespaces=false", "--watch-for-secrets", "--key-prefix", "p-"},
			renew: "0s", order: "CertNotBefore", prefix: "p-",
		},
		"a trailing flag without a value is not set": {
			args:  []string{"--key-renew-period"},
			renew: "720h0m0s", order: "CertNotBefore", prefix: "sealed-secrets-key",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := controllerDeployment(tc.args...)
			c := &d.Spec.Template.Spec.Containers[0]
			if tc.command != nil {
				c.Command = tc.command
			}
			c.Env, c.EnvFrom = tc.env, tc.envFrom
			got := readSettings(d)
			if got.keyRenewPeriod != tc.renew || got.keyOrderPriority != tc.order || got.keyPrefix != tc.prefix {
				t.Fatalf("settings = %+v, want renew %q, order %q, prefix %q", got, tc.renew, tc.order, tc.prefix)
			}
		})
	}
}

// Only the controller's own container counts, not a sidecar's flags.
func TestReadSettings_ControllerContainerOnly(t *testing.T) {
	d := controllerDeployment("--key-renew-period=0")
	d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers,
		corev1.Container{Name: "sidecar", Args: []string{"--key-renew-period=24h"}})
	if got := readSettings(d).keyRenewPeriod; got != "0s" {
		t.Fatalf("renew period = %q, want the controller's 0s", got)
	}
	unnamed := &appsv1.Deployment{}
	unnamed.Spec.Template.Spec.Containers = []corev1.Container{{Name: "a"}, {Name: "b"}}
	if got := readSettings(unnamed); got != (controllerSettings{keyPrefix: defaultKeyPrefix}) {
		t.Fatalf("settings without a controller container = %+v, want unknown", got)
	}
}

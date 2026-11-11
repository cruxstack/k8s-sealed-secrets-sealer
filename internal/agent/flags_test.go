package agent

import (
	"slices"
	"strings"
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

// The agent must read which SealedSecrets the controller watches as the
// controller does (sealed-secrets v0.41, pkg/controller/main.go): every
// namespace unless --all-namespaces is false or --additional-namespaces is
// set at all, and then its own and the additional ones.
func TestReadWatchScope(t *testing.T) {
	envVar := func(name, value string) corev1.EnvVar { return corev1.EnvVar{Name: name, Value: value} }
	fieldRef := func(path string) corev1.EnvVar {
		return corev1.EnvVar{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: path}}}
	}
	fromConfigMap := []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}}}}
	cases := map[string]struct {
		args       []string
		env        []corev1.EnvVar
		envFrom    []corev1.EnvFromSource
		namespaces []string
		selector   string
		err        string
	}{
		"every namespace by default": {},
		"its own namespace only": {
			args: []string{"--all-namespaces=false"}, namespaces: []string{ns},
		},
		// the local stack's controllers
		"its own and an additional one": {
			args:       []string{"--update-status", "--key-renew-period=0", "--all-namespaces=false", "--additional-namespaces", "apps"},
			namespaces: []string{"apps", ns},
		},
		"additional namespaces alone narrow it": {
			args: []string{"--additional-namespaces= b, a,,b"}, namespaces: []string{"a", "b", ns},
		},
		// the controller cannot find a namespace by a name none can have
		"names no namespace can have are left out": {
			args: []string{"--additional-namespaces=My_Apps, apps"}, namespaces: []string{"apps", ns},
		},
		"additional namespaces of blanks narrow it to its own": {
			args: []string{"--additional-namespaces= "}, namespaces: []string{ns},
		},
		"the flag alone is true, and the last occurrence wins": {
			args: []string{"--all-namespaces=false", "--all-namespaces"},
		},
		// pflag takes "false" as an argument, not the flag's value
		"a boolean flag takes no separate value": {
			args: []string{"--all-namespaces", "false"},
		},
		"variables when no flag is set": {
			env:        []corev1.EnvVar{envVar("SEALED_SECRETS_ALL_NAMESPACES", "false"), envVar("SEALED_SECRETS_ADDITIONAL_NAMESPACES", "apps"), envVar("SEALED_SECRETS_LABEL_SELECTOR", "team=a")},
			namespaces: []string{"apps", ns}, selector: "team=a",
		},
		"a flag overrides its variable": {
			args: []string{"--all-namespaces=true"}, env: []corev1.EnvVar{envVar("SEALED_SECRETS_ALL_NAMESPACES", "false")},
		},
		// pflag sets the flag false, and the controller ignores the error
		"a variable that is not a boolean is false": {
			env: []corev1.EnvVar{envVar("SEALED_SECRETS_ALL_NAMESPACES", "no thanks")}, namespaces: []string{ns},
		},
		"a label selector": {
			args: []string{"--label-selector", "team=a"}, selector: "team=a",
		},
		"POD_NAMESPACE names its own namespace": {
			args: []string{"--all-namespaces=false"}, env: []corev1.EnvVar{envVar("POD_NAMESPACE", "elsewhere")}, namespaces: []string{"elsewhere"},
		},
		"POD_NAMESPACE from the pod's namespace": {
			args: []string{"--all-namespaces=false"}, env: []corev1.EnvVar{fieldRef("metadata.namespace")}, namespaces: []string{ns},
		},
		"POD_NAMESPACE empty": {
			args: []string{"--all-namespaces=false"}, env: []corev1.EnvVar{envVar("POD_NAMESPACE", "")}, namespaces: []string{ns},
		},
		"POD_NAMESPACE from elsewhere": {
			args: []string{"--all-namespaces=false"}, env: []corev1.EnvVar{fieldRef("metadata.name")},
			err: "POD_NAMESPACE is set where the agent cannot read it",
		},
		"a flag the controller refuses": {
			args: []string{"--all-namespaces=maybe"}, err: "--all-namespaces is set where the agent cannot read it",
		},
		"envFrom may set anything": {
			envFrom: fromConfigMap, err: "--all-namespaces is set where the agent cannot read it",
		},
		"additional namespaces from a variable it cannot read": {
			env: []corev1.EnvVar{{Name: "SEALED_SECRETS_ADDITIONAL_NAMESPACES", ValueFrom: &corev1.EnvVarSource{}}},
			err: "--additional-namespaces is set where the agent cannot read it",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := controllerDeployment(tc.args...)
			d.Spec.Template.Spec.Containers[0].Env = tc.env
			d.Spec.Template.Spec.Containers[0].EnvFrom = tc.envFrom
			got, err := readWatchScope(d)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.namespaces, tc.namespaces) || (got.namespaces == nil) != (tc.namespaces == nil) || got.labelSelector != tc.selector {
				t.Fatalf("scope = %+v, want namespaces %v, selector %q", got, tc.namespaces, tc.selector)
			}
		})
	}
}

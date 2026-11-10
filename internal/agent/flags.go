package agent

import (
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// The controller's settings are read from its Deployment the way the
// controller reads them (sealed-secrets v0.41, cmd/controller/main.go). Each
// flag can also be set by an environment variable, SEALED_SECRETS_ and the
// flag's name (KEY_RENEW_PERIOD for --key-renew-period), which a flag on the
// command line overrides. Of several occurrences of a flag the last wins,
// and --rotate-period is the old name of --key-renew-period: both set the
// same value.

// Controller defaults, used when neither a flag nor a variable sets them.
const (
	defaultKeyRenewPeriod   = 30 * 24 * time.Hour
	defaultKeyOrderPriority = "CertNotBefore"
	defaultKeyPrefix        = "sealed-secrets-key"
)

// Key orders the controller knows.
const (
	orderCertNotBefore      = "CertNotBefore"
	orderSecretCreationTime = "SecretCreationTimestamp"
)

// flagEnvPrefix starts the environment variable of every controller flag.
const flagEnvPrefix = "SEALED_SECRETS_"

// renewPeriodFlags set the key renew period; the second is its deprecated
// name.
var renewPeriodFlags = []string{"key-renew-period", "rotate-period"}

// controllerBoolFlags are the controller's flags that take no separate
// value: in "--update-status false", "false" is an argument, not the flag's
// value.
var controllerBoolFlags = []string{
	"accept-deprecated-v1-data", "all-namespaces", "log-info-stdout", "metrics-omit-secret-labels",
	"old-gc-behavior", "skip-recreate", "update-status", "version", "watch-for-secrets",
}

// controllerSettings are the controller settings the agent works with. Each
// is empty when the agent cannot tell it, for example when a variable comes
// from a ConfigMap (envFrom) or the Deployment cannot be read.
type controllerSettings struct {
	// keyRenewPeriod is a duration, "0s" when renewal is off.
	keyRenewPeriod string
	// keyOrderPriority is CertNotBefore or SecretCreationTimestamp, the only
	// orders the controller has.
	keyOrderPriority string
	// keyPrefix names the key Secrets the controller creates.
	keyPrefix string
}

// readSettings reads the settings of the controller container in d.
func readSettings(d *appsv1.Deployment) controllerSettings {
	i, err := controllerContainerIndex(d)
	if err != nil {
		return controllerSettings{keyPrefix: defaultKeyPrefix}
	}
	c := d.Spec.Template.Spec.Containers[i]
	return controllerSettings{
		keyRenewPeriod:   renewPeriodOf(lookupSetting(c, renewPeriodFlags...)),
		keyOrderPriority: keyOrderOf(lookupSetting(c, "key-order-priority")),
		keyPrefix:        keyPrefixOf(lookupSetting(c, "key-prefix")),
	}
}

// setting is one controller setting as its container sets it.
type setting struct {
	value string
	// set is false when nothing sets it, so the controller's default
	// applies.
	set bool
	// known is false when it may be set but the agent cannot read the
	// value: a variable from valueFrom or envFrom, or a value that refers
	// to other variables, which the kubelet expands.
	known bool
	// fromEnv is true when an environment variable sets it.
	fromEnv bool
}

// lookupSetting finds the value of the flag names (aliases of one setting)
// in a container. A flag on the command line wins; otherwise the controller
// sets flags from variables in the order of their names, so the variable of
// the name that sorts last wins.
func lookupSetting(c corev1.Container, names ...string) setting {
	argv := append(slices.Clone(c.Command), c.Args...)
	if v, ok := lastFlag(argv, names); ok {
		return setting{value: v, set: true, known: !strings.Contains(v, "$(")}
	}
	var out setting
	for _, name := range slices.Sorted(slices.Values(names)) {
		if s := envSetting(c, flagEnvPrefix+strings.ToUpper(strings.ReplaceAll(name, "-", "_"))); s.set {
			out = s
		}
	}
	return out
}

// envSetting finds an environment variable as the kubelet sets it: a
// variable in env overrides one from envFrom, and of duplicates in env the
// last wins.
func envSetting(c corev1.Container, name string) setting {
	for i := len(c.Env) - 1; i >= 0; i-- {
		e := c.Env[i]
		if e.Name != name {
			continue
		}
		known := e.ValueFrom == nil && !strings.Contains(e.Value, "$(")
		return setting{value: e.Value, set: true, known: known, fromEnv: true}
	}
	for _, from := range c.EnvFrom {
		if strings.HasPrefix(name, from.Prefix) {
			// a ConfigMap or Secret the agent cannot read may set it
			return setting{set: true, fromEnv: true}
		}
	}
	return setting{}
}

// renewPeriodOf returns the renew period a setting gives the controller.
func renewPeriodOf(s setting) string {
	switch {
	case !s.set:
		return defaultKeyRenewPeriod.String()
	case !s.known:
		return ""
	}
	d, err := time.ParseDuration(s.value)
	if err != nil {
		if s.fromEnv {
			// the controller ignores the error, and its flag parser has
			// already set the period to zero
			return time.Duration(0).String()
		}
		// the controller refuses to start with it
		return ""
	}
	return d.String()
}

// keyOrderOf returns the key order a setting gives the controller: it orders
// by NotBefore unless told SecretCreationTimestamp exactly.
func keyOrderOf(s setting) string {
	switch {
	case !s.set:
		return defaultKeyOrderPriority
	case !s.known:
		return ""
	case s.value == orderSecretCreationTime:
		return orderSecretCreationTime
	default:
		return orderCertNotBefore
	}
}

// keyPrefixOf returns the key prefix a setting gives the controller, or the
// default when it is unknown or empty: the prefix only names a restored key
// Secret, and the controller finds its keys by label.
func keyPrefixOf(s setting) string {
	if !s.set || !s.known || s.value == "" {
		return defaultKeyPrefix
	}
	return s.value
}

// flagArg is one long flag with a value on a command line.
type flagArg struct {
	name  string
	value string
	// at is the flag's index in argv; its value is at at+1 unless inline
	// (--name=value).
	at     int
	inline bool
}

// parseFlags reads a command line as the controller's flag parser (pflag)
// does: "--name=value", or "--name value" for a flag that is not boolean;
// nothing after "--" is a flag; and an argument with a single dash is never
// a long flag. It returns the flags that have a value, in order, and the
// index of "--" (len(argv) when there is none). A flag the agent does not
// know is taken as boolean when the next argument is another flag.
func parseFlags(argv []string) ([]flagArg, int) {
	var out []flagArg
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			return out, i
		}
		if !strings.HasPrefix(a, "--") {
			continue
		}
		name, value, inline := strings.Cut(a[2:], "=")
		if inline {
			out = append(out, flagArg{name: name, value: value, at: i, inline: true})
			continue
		}
		if slices.Contains(controllerBoolFlags, name) || i+1 >= len(argv) || strings.HasPrefix(argv[i+1], "--") {
			continue
		}
		out = append(out, flagArg{name: name, value: argv[i+1], at: i})
		i++
	}
	return out, len(argv)
}

// lastFlag returns the value of the last occurrence of any of names.
func lastFlag(argv []string, names []string) (string, bool) {
	flags, _ := parseFlags(argv)
	for i := len(flags) - 1; i >= 0; i-- {
		if slices.Contains(names, flags[i].name) {
			return flags[i].value, true
		}
	}
	return "", false
}

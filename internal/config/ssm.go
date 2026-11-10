package config

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"golang.org/x/sync/errgroup"
)

// ssmParameterARN matches an SSM Parameter Store parameter ARN in any AWS
// partition. Its fourth field is the parameter's region.
var ssmParameterARN = regexp.MustCompile(`^arn:aws(-[a-z]+)*:ssm:[a-z0-9-]+:[0-9]{12}:parameter/[A-Za-z0-9_.\-/]+$`)

// IsSSMParameterARN reports whether v names an SSM parameter by its ARN.
func IsSSMParameterARN(v string) bool { return ssmParameterARN.MatchString(v) }

// ParameterReader returns the value of the SSM parameter an ARN names,
// decrypted when it is a SecureString.
type ParameterReader func(ctx context.Context, arn string) (string, error)

// resolveTimeout bounds reading every parameter at start.
const resolveTimeout = 15 * time.Second

// rereadSettings are read from SSM by loadControlPlanes rather than
// resolveParameters, which keeps their ARNs so the control plane can read
// them again: the agent registry may change while it runs.
var rereadSettings = []string{"APP_REGISTRY"}

// resolveParameters returns a lookup over environ in which every APP_
// variable whose value is an SSM parameter ARN reads as that parameter's
// value, except rereadSettings. newReader is called only when there is a
// parameter to read, so a process with no ARNs needs no AWS credentials.
// Values are never logged or put in errors.
func resolveParameters(ctx context.Context, environ []string, newReader func(context.Context) (ParameterReader, error)) (lookupFunc, error) {
	vars := map[string]string{}
	var names []string
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		vars[k] = v
		if strings.HasPrefix(k, "APP_") && IsSSMParameterARN(v) && !slices.Contains(rereadSettings, k) {
			names = append(names, k)
		}
	}
	lookup := func(key string) (string, bool) {
		v, ok := vars[key]
		return v, ok
	}
	if len(names) == 0 {
		return lookup, nil
	}
	sort.Strings(names)

	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	read, err := newReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read settings from SSM: %w", err)
	}
	values := make([]string, len(names))
	errs := make([]error, len(names))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)
	for i, name := range names {
		g.Go(func() error {
			v, err := read(gctx, vars[name])
			if err != nil {
				errs[i] = fmt.Errorf("%s: failed to read SSM parameter %s: %w", name, vars[name], err)
				return nil
			}
			values[i] = v
			return nil
		})
	}
	_ = g.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid configuration:\n%w", err)
	}
	for i, name := range names {
		vars[name] = values[i]
	}
	return lookup, nil
}

// NewParameterReader returns a ParameterReader that uses the AWS SDK's
// default credentials and calls each parameter's own region. The control
// plane uses it to read its registry again.
func NewParameterReader(ctx context.Context) (ParameterReader, error) {
	return newSSMReader(ctx)
}

// newSSMReader reads parameters with the AWS SDK's default credentials, in
// each parameter's own region.
func newSSMReader(ctx context.Context) (ParameterReader, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	clients := map[string]*ssm.Client{}
	return func(ctx context.Context, arn string) (string, error) {
		region := strings.Split(arn, ":")[3]
		mu.Lock()
		client, ok := clients[region]
		if !ok {
			client = ssm.NewFromConfig(awsCfg, func(o *ssm.Options) { o.Region = region })
			clients[region] = client
		}
		mu.Unlock()
		// GetParameter takes the full ARN, which also reaches parameters
		// shared from another account
		out, err := client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(arn), WithDecryption: aws.Bool(true)})
		if err != nil {
			return "", err
		}
		if out.Parameter == nil || out.Parameter.Value == nil {
			return "", errors.New("the parameter has no value")
		}
		return *out.Parameter.Value, nil
	}, nil
}

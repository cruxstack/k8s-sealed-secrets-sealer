package agent

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestSTSEndpoint(t *testing.T) {
	for region, want := range map[string]string{
		"us-east-2":  "https://sts.us-east-2.amazonaws.com/",
		"cn-north-1": "https://sts.cn-north-1.amazonaws.com.cn/",
	} {
		if got := stsEndpoint(region); got != want {
			t.Errorf("%s: %s, want %s", region, got, want)
		}
	}
}

// Requests signed in the same second would be identical, and the control
// plane accepts each signed request once.
func TestAWSIdentity_NeverSignsTwiceInOneSecond(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 100, time.UTC)
	id, err := NewAWSIdentity(AWSIdentityOptions{
		Credentials: credentials.StaticCredentialsProvider{Value: aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}},
		Region:      "us-east-1",
		Audience:    "https://sealer.example.com",
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 3 {
		req, err := id.LoginRequest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		date := req.AWS.Headers["X-Amz-Date"]
		if seen[date] {
			t.Fatalf("signed twice at %s", date)
		}
		seen[date] = true
	}
	if !seen["20260102T030405Z"] || !seen["20260102T030407Z"] {
		t.Fatalf("signing times = %v", seen)
	}
}

package protocol

import (
	"testing"
	"time"
)

func TestSealFits(t *testing.T) {
	cases := []struct {
		value, targets int
		want           bool
	}{
		{1, 1, true},
		{MaxSealValueBytes, 3, true},
		{MaxSealValueBytes, 4, false}, // too much for one DynamoDB item
		{MaxSealValueBytes + 1, 1, false},
		{100, MaxSealTargets, true},
		{100, MaxSealTargets + 1, false},
	}
	for _, tc := range cases {
		if got := SealFits(tc.value, tc.targets); got != tc.want {
			t.Errorf("SealFits(%d, %d) = %v, want %v", tc.value, tc.targets, got, tc.want)
		}
	}
}

func TestNegotiate(t *testing.T) {
	ours := []string{"v2", "v1"}
	cases := map[string]struct {
		in   CheckIn
		want string
	}{
		"single field":               {CheckIn{Protocol: "v1"}, "v1"},
		"list":                       {CheckIn{Protocols: []string{"v1", "v2"}}, "v2"},
		"list with the single field": {CheckIn{Protocol: "v1", Protocols: []string{"v1", "v3"}}, "v1"},
		"newer agent":                {CheckIn{Protocol: "v3", Protocols: []string{"v3", "v2"}}, "v2"},
		"none in common":             {CheckIn{Protocol: "v9", Protocols: []string{"v8"}}, ""},
		"none sent":                  {CheckIn{}, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := Negotiate(tc.in, ours)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("Negotiate = %q, %v, want %q", got, ok, tc.want)
			}
		})
	}
}

func TestFingerprintPath_RoundTrips(t *testing.T) {
	fp := "SHA256:ab+c/d="
	if seg := FingerprintPath(fp); seg != "SHA256:ab-c_d=" || ParseFingerprintPath(seg) != fp {
		t.Fatalf("FingerprintPath(%q) = %q", fp, seg)
	}
}

func TestHealthWindow(t *testing.T) {
	for interval, want := range map[time.Duration]time.Duration{
		0:                45 * time.Second,
		15 * time.Second: 45 * time.Second,
		5 * time.Second:  45 * time.Second,
		time.Minute:      3 * time.Minute,
		24 * time.Hour:   15 * time.Minute,
	} {
		if got := HealthWindow(interval); got != want {
			t.Errorf("HealthWindow(%s) = %s, want %s", interval, got, want)
		}
	}
}

package protocol

import (
	"encoding/json"
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

// A usage report says "every namespace" with null, and leaves out the keys
// when no key seals a value.
func TestKeyUsage_JSON(t *testing.T) {
	b, err := json.Marshal(KeyUsage{ScannedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"scanned_at":"2026-11-10T12:00:00Z","namespaces":null,"sealed_secrets":0,"values":0,"unmatched":0}`
	if string(b) != want {
		t.Fatalf("KeyUsage = %s, want %s", b, want)
	}
}

// Every capability another needs is a capability, and every command's
// capability is one.
func TestCapabilities(t *testing.T) {
	for c, need := range CapabilityNeeds {
		if !IsCapability(c) || !IsCapability(need) || c == need {
			t.Errorf("CapabilityNeeds[%q] = %q", c, need)
		}
	}
	for cmd, c := range CommandCapability {
		if !IsCapability(c) {
			t.Errorf("command %s needs unknown capability %q", cmd, c)
		}
	}
	if CommandCapability[CommandKeysDelete] != CapabilityCleanup {
		t.Error("keys.delete.v1 is not cleanup's")
	}
	if CommandCapability[CommandReseal] != CapabilityReseal || CapabilityNeeds[CapabilityReseal] != CapabilityKeys {
		t.Error("reseal.v1 is not reseal's, or reseal does not need keys")
	}
}

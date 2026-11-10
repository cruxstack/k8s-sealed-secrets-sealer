package protocol

import "testing"

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

func TestFingerprintPath_RoundTrips(t *testing.T) {
	fp := "SHA256:ab+c/d="
	if seg := FingerprintPath(fp); seg != "SHA256:ab-c_d=" || ParseFingerprintPath(seg) != fp {
		t.Fatalf("FingerprintPath(%q) = %q", fp, seg)
	}
}

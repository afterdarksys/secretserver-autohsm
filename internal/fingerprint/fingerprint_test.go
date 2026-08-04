package fingerprint

import "testing"

func TestOfIsStable(t *testing.T) {
	a := Of([]byte("share-material"))
	b := Of([]byte("share-material"))
	if a != b {
		t.Fatalf("fingerprint not stable: %s != %s", a, b)
	}
}

func TestOfDistinguishesInputs(t *testing.T) {
	if Of([]byte("share-a")) == Of([]byte("share-b")) {
		t.Fatal("distinct inputs produced identical fingerprints")
	}
}

// Negative: the fingerprint must never contain the secret itself.
func TestOfDoesNotLeakSecret(t *testing.T) {
	secret := []byte("hunter2-super-secret-unseal-share")
	fp := Of(secret)
	if len(fp) == 0 {
		t.Fatal("empty fingerprint")
	}
	// The digest must not embed the plaintext in any form.
	if containsSub(fp, "hunter2") {
		t.Fatalf("fingerprint leaked plaintext: %s", fp)
	}
}

// Negative: an empty secret must be flagged, not silently digested. An empty
// share is an operational bug and must be visible, not look like a real value.
func TestOfEmptyIsExplicit(t *testing.T) {
	if got := Of(nil); got != "sha256:<empty>" {
		t.Fatalf("nil input: got %q", got)
	}
	if got := Of([]byte{}); got != "sha256:<empty>" {
		t.Fatalf("empty input: got %q", got)
	}
}

// Negative: output must stay bounded so a huge secret cannot flood logs.
func TestOfLengthIsBounded(t *testing.T) {
	big := make([]byte, 1<<20)
	fp := Of(big)
	if want := len("sha256:") + truncatedLen; len(fp) != want {
		t.Fatalf("unbounded fingerprint length %d, want %d", len(fp), want)
	}
}

func containsSub(haystack, needle string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

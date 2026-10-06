package shamir

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// FIPS-197 section 4.2 worked example: {57} * {83} = {c1} in the AES field,
// which is the field Vault uses.
func TestFieldMatchesAESField(t *testing.T) {
	if got := mul(0x57, 0x83); got != 0xc1 {
		t.Fatalf("mul(57,83)=%02x, want c1", got)
	}
	if got := mul(0x57, 0x13); got != 0xfe {
		t.Fatalf("mul(57,13)=%02x, want fe", got)
	}
	for a := 1; a < 256; a++ {
		if mul(uint8(a), inv(uint8(a))) != 1 {
			t.Fatalf("inverse of %02x wrong", a)
		}
		for b := 0; b < 256; b += 7 {
			if mul(uint8(a), uint8(b)) != mul(uint8(b), uint8(a)) {
				t.Fatal("mul not commutative")
			}
		}
	}
}

// split is a test-only Shamir split in Vault's format (y bytes then x).
func split(t *testing.T, secret []byte, n, k int, xs []uint8) [][]byte {
	t.Helper()
	parts := make([][]byte, n)
	for i := range parts {
		parts[i] = make([]byte, len(secret)+1)
		parts[i][len(secret)] = xs[i]
	}
	coeff := make([]byte, k)
	for b, s := range secret {
		coeff[0] = s
		if _, err := rand.Read(coeff[1:]); err != nil {
			t.Fatal(err)
		}
		for i := range parts {
			var y uint8
			for d := k - 1; d >= 0; d-- {
				y = mul(y, xs[i]) ^ coeff[d]
			}
			parts[i][b] = y
		}
	}
	return parts
}

func randomXs(t *testing.T, n int) []uint8 {
	xs := make([]uint8, 0, n)
	seen := map[uint8]bool{0: true}
	for len(xs) < n {
		b := make([]byte, 1)
		rand.Read(b)
		if !seen[b[0]] {
			seen[b[0]] = true
			xs = append(xs, b[0])
		}
	}
	return xs
}

func TestCombineRandomVectors(t *testing.T) {
	for iter := 0; iter < 200; iter++ {
		secret := make([]byte, 32)
		rand.Read(secret)
		parts := split(t, secret, 5, 3, randomXs(t, 5))
		for _, sel := range [][]int{{0, 1, 2}, {2, 3, 4}, {4, 0, 2}, {1, 3, 4}} {
			got, err := Combine([][]byte{parts[sel[0]], parts[sel[1]], parts[sel[2]]})
			if err != nil || !bytes.Equal(got, secret) {
				t.Fatalf("combine %v: %x != %x (%v)", sel, got, secret, err)
			}
		}
		if err := Consistent(parts, 3); err != nil {
			t.Fatal(err)
		}
		if err := Consistent(parts[:4], 3); err != nil {
			t.Fatal(err)
		}
		// Two shares are below threshold 3: they must not give the secret.
		if got, _ := Combine(parts[:2]); bytes.Equal(got, secret) {
			t.Fatal("two shares reconstructed a threshold-3 secret")
		}
	}
}

// Negative: a random share, a share from another split, and a duplicated
// share in the fourth position are all caught.
func TestConsistentRejectsBadFourthShare(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	xs := randomXs(t, 5)
	parts := split(t, secret, 5, 3, xs)

	random := make([]byte, 33)
	rand.Read(random)
	random[32] = xs[3]
	other := split(t, secret, 5, 3, xs)[3] // same secret, different polynomial
	for name, fourth := range map[string][]byte{
		"random y, right x":           random,
		"share of another polynomial": other,
		"copy of share 2":             append([]byte(nil), parts[1]...),
		"zero x":                      append(append([]byte(nil), parts[3][:32]...), 0),
		"short":                       parts[3][:20],
	} {
		if err := Consistent([][]byte{parts[0], parts[1], parts[2], fourth}, 3); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCombineRejectsMalformed(t *testing.T) {
	if _, err := Combine([][]byte{{1, 2}}); err == nil {
		t.Fatal("one part accepted")
	}
	if _, err := Combine([][]byte{{1}, {2}}); err == nil {
		t.Fatal("one-byte parts accepted")
	}
	if _, err := Combine([][]byte{{1, 2, 3}, {1, 2}}); err == nil {
		t.Fatal("unequal lengths accepted")
	}
	if err := Consistent([][]byte{{1, 2}, {1, 3}, {1, 4}}, 3); err == nil {
		t.Fatal("cross-check without a spare share accepted")
	}
}

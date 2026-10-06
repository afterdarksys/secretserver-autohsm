// Asset: shamir-combine
// Purpose: Recombine and cross-check Vault-format Shamir shares on the operator workstation.
// Threats: Lets vaultkeeper prove that rekey shares Vault never verified (share 4, and
// share 5 once the offline key is present) lie on the same polynomial as the shares Vault
// did verify, so a substituted, duplicated or random share is caught before anything is
// delivered, deleted or shredded. Rejects malformed input: fewer than two parts, unequal
// or too-short lengths, a zero or duplicate x coordinate. Field arithmetic is
// branch-free on secret values. Does NOT split secrets (Vault does that), does NOT
// protect the recombined secret once returned (callers must wipe it), and is only as
// good as the claim that the reference shares are genuine.
// Deps: none (stdlib only)
// Example: ok, err := shamir.Consistent([][]byte{s1, s2, s3, s4}, 3)
// Status: tested
// License: MIT
// Provenance: original; written to match Vault's share format and field
package shamir

import (
	"crypto/subtle"
	"fmt"
)

// Share format (Vault's): the y values, one byte per secret byte, followed
// by a single x-coordinate byte. The field is GF(2^8) with the reduction
// polynomial x^8 + x^4 + x^3 + x + 1 (0x11b), the same as Vault's.

// mul multiplies in GF(2^8) without branching on its inputs.
func mul(a, b uint8) uint8 {
	var r uint8
	for i := 7; i >= 0; i-- {
		// r = r*x (reduced) + (bit i of b) * a
		r = (r << 1) ^ (uint8(-(int8(r) >> 7 & 1)) & 0x1b) ^ (uint8(-int8(b>>uint(i)&1)) & a)
	}
	return r
}

// inv returns a^254 = a^-1 (and 0 for 0), by square-and-multiply over the
// fixed exponent, so the sequence of operations does not depend on a.
func inv(a uint8) uint8 {
	result := uint8(1)
	base := a
	for e := 254; e > 0; e >>= 1 {
		if e&1 == 1 {
			result = mul(result, base)
		}
		base = mul(base, base)
	}
	return result
}

// interpolateAtZero evaluates, at x = 0, the polynomial through (xs[i], ys[i]).
func interpolateAtZero(xs, ys []uint8) uint8 {
	var result uint8
	for i := range xs {
		basis := uint8(1)
		for j := range xs {
			if i == j {
				continue
			}
			// (0 - x_j) / (x_i - x_j); subtraction is xor in GF(2^8).
			basis = mul(basis, mul(xs[j], inv(xs[i]^xs[j])))
		}
		result ^= mul(ys[i], basis)
	}
	return result
}

// Combine reconstructs the secret from parts in Vault's share format. The
// caller must wipe the result.
func Combine(parts [][]byte) ([]byte, error) {
	if len(parts) < 2 {
		return nil, fmt.Errorf("shamir: need at least two parts")
	}
	n := len(parts[0])
	if n < 2 {
		return nil, fmt.Errorf("shamir: parts must be at least two bytes")
	}
	xs := make([]uint8, len(parts))
	seen := map[uint8]bool{}
	for i, p := range parts {
		if len(p) != n {
			return nil, fmt.Errorf("shamir: parts have different lengths")
		}
		x := p[n-1]
		if x == 0 {
			return nil, fmt.Errorf("shamir: part %d has x coordinate 0", i+1)
		}
		if seen[x] {
			return nil, fmt.Errorf("shamir: duplicate x coordinate")
		}
		seen[x] = true
		xs[i] = x
	}
	secret := make([]byte, n-1)
	ys := make([]uint8, len(parts))
	for b := range secret {
		for i, p := range parts {
			ys[i] = p[b]
		}
		secret[b] = interpolateAtZero(xs, ys)
	}
	for i := range ys {
		ys[i] = 0
	}
	return secret, nil
}

// Consistent reports whether every threshold-sized subset of parts that
// includes parts[0] combines to the same secret, i.e. whether all parts lie
// on one polynomial of degree threshold-1. len(parts) must exceed
// threshold. Secrets are compared in constant time and wiped.
func Consistent(parts [][]byte, threshold int) error {
	if threshold < 2 || len(parts) <= threshold {
		return fmt.Errorf("shamir: need more than threshold (%d) parts to cross-check, got %d", threshold, len(parts))
	}
	var ref []byte
	defer func() { wipe(ref) }()
	ok := true
	for _, subset := range subsets(len(parts), threshold) {
		sel := make([][]byte, len(subset))
		for i, k := range subset {
			sel[i] = parts[k]
		}
		s, err := Combine(sel)
		if err != nil {
			return err
		}
		if ref == nil {
			ref = s
			continue
		}
		if subtle.ConstantTimeCompare(ref, s) != 1 {
			ok = false
		}
		wipe(s)
	}
	if !ok {
		return fmt.Errorf("shamir: shares do not lie on one polynomial (substituted, duplicated or corrupted share)")
	}
	return nil
}

// subsets lists every k-subset of 0..n-1 that contains 0, in order.
func subsets(n, k int) [][]int {
	var out [][]int
	var rec func(start int, cur []int)
	rec = func(start int, cur []int) {
		if len(cur) == k {
			out = append(out, append([]int(nil), cur...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(cur, i))
		}
	}
	rec(1, []int{0})
	return out
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

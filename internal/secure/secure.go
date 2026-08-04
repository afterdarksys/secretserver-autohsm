// Asset: secure-bytes
// Purpose: Best-effort zeroization for plaintext key material held in memory.
// Threats: Limits the window in which an unseal key share is recoverable from
// process memory (core dumps, swap, heap inspection after use). Does NOT protect
// against an attacker with live process access at the moment of use, does NOT
// prevent the Go runtime from having copied the value before Wipe is called, and
// is NOT a substitute for keeping material inside the HSM.
// Deps: none
// Example: defer secure.Wipe(share); ...
// Status: tested
// License: proprietary
// Provenance: original
package secure

// Wipe overwrites b with zeroes. Safe to call on nil.
//
// Callers must keep key material in []byte and never convert it to string:
// Go strings are immutable, so a string copy can never be wiped.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// WipeAll wipes every buffer in bs.
func WipeAll(bs [][]byte) {
	for _, b := range bs {
		Wipe(b)
	}
}

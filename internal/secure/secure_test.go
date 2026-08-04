package secure

import "testing"

func TestWipe(t *testing.T) {
	b := []byte("plaintext-key-material")
	Wipe(b)
	for i, value := range b {
		if value != 0 {
			t.Fatalf("byte %d was not wiped", i)
		}
	}
	Wipe(nil)
}

func TestWipeAll(t *testing.T) {
	parts := [][]byte{[]byte("one"), nil, []byte("two")}
	WipeAll(parts)
	for i, part := range parts {
		for _, value := range part {
			if value != 0 {
				t.Fatalf("buffer %d was not wiped", i)
			}
		}
	}
}

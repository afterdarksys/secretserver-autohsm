package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/watch"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"sealed", sealedError{msg: "sealed"}, exitSealed},
		{"wrapped sealed", fmt.Errorf("status: %w", sealedError{msg: "sealed"}), exitSealed},
		{"terminal", fmt.Errorf("watch: %w", watch.ErrTerminal), exitTerminal},
		{"ordinary", errors.New("network down"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.err); got != tt.want {
				t.Fatalf("exitCode()=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestReadShare(t *testing.T) {
	for name, input := range map[string]string{
		"newline": "share-value\n",
		"crlf":    "share-value\r\n",
		"eof":     "share-value",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readShare(bytes.NewBufferString(input))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "share-value" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

func TestReadShareRejectsUnsafeInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"empty":     nil,
		"blank":     []byte("\n"),
		"multiline": []byte("share-one\nshare-two\n"),
		"oversized": bytes.Repeat([]byte{'x'}, maxShareSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readShare(bytes.NewReader(input)); err == nil {
				t.Fatal("unsafe share input accepted")
			}
		})
	}
}

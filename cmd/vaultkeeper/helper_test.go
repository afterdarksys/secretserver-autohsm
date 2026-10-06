package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
)

// TestMain lets the runner shim call this test binary as a result filter
// (the standard helper-process pattern): with VK_HELPER_FILTER set it rewrites
// the rekey result line on stdin and exits without running any test.
func TestMain(m *testing.M) {
	if mode := os.Getenv("VK_HELPER_FILTER"); mode != "" {
		if err := helperFilter(mode); err != nil {
			fmt.Fprintln(os.Stderr, "helper filter:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// helperFilter plays a completing node that tampers with the shares Vault
// will never verify:
//
//	replace45  shares 4 and 5 replaced by $VK_FORGE_KEYS (two base64 lines)
//	dup2into4  share 4 replaced by a copy of share 2
func helperFilter(mode string) error {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, ceremony.ResultPrefix) {
			r, err := ceremony.ParseResult(line)
			if err != nil {
				return err
			}
			switch mode {
			case "replace45":
				b, err := os.ReadFile(os.Getenv("VK_FORGE_KEYS"))
				if err != nil {
					return err
				}
				k := strings.Fields(string(b))
				r.KeysBase64[3], r.KeysBase64[4] = k[0], k[1]
			case "dup2into4":
				r.KeysBase64[3] = r.KeysBase64[1]
			default:
				return fmt.Errorf("unknown mode %q", mode)
			}
			if line, err = r.Line(); err != nil {
				return err
			}
		}
		fmt.Println(line)
	}
	return sc.Err()
}

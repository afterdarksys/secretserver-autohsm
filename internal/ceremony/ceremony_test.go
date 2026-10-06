package ceremony

import (
	"errors"
	"strings"
	"testing"

	"github.com/afterdarksys/secretserver-autohsm/internal/vaultclient"
)

const (
	op    = "600e44ad55f1d7c04f52946ab051837018556301"
	off   = "151d8ce90777db86be03e5eefb15cc9a4992b487"
	nonce = "f4fef122-4056-7c7a-0a6d-37707c6a03ec"
)

func TestFingerprintEqual(t *testing.T) {
	if !FingerprintEqual(op, strings.ToUpper(op)) {
		t.Fatal("case-folded fingerprints differ")
	}
	if FingerprintEqual("", "") || FingerprintEqual(op, off) || FingerprintEqual(op, op[:39]) {
		t.Fatal("unequal or empty fingerprints matched")
	}
}

func TestCheckGenerateRootAcceptsPinned(t *testing.T) {
	st := &vaultclient.GenerateRootStatus{Started: true, Nonce: nonce, Required: 3, PGPFingerprint: op}
	if err := CheckGenerateRoot(st, op); err != nil {
		t.Fatal(err)
	}
}

func TestResultRoundTripAndStrictParsing(t *testing.T) {
	r := &Result{Op: OpGenerateRoot, Nonce: nonce, EncodedToken: "QUJD", PGPFingerprint: op}
	line, err := r.Line()
	if err != nil {
		t.Fatal(err)
	}
	got, err := FindResult([]byte("contribute op=generate-root nonce=f4fef122 progress=3/3\n" + line + "\n"))
	if err != nil || got == nil || got.EncodedToken != "QUJD" {
		t.Fatalf("%+v %v", got, err)
	}
	if none, err := FindResult([]byte("contribute op=rekey nonce=f4fef122 progress=1/3\n")); none != nil || err != nil {
		t.Fatal("result found where there is none")
	}
	bad := []string{
		line + "\n" + line,
		ResultPrefix + `{"op":"unseal","nonce":"` + nonce + `"}`,
		ResultPrefix + `{"op":"rekey","nonce":"zz"}`,
		ResultPrefix + `{"op":"rekey","nonce":"` + nonce + `","otp":"x"}`,
		ResultPrefix + `not json`,
		line + ` trailing`,
		line + `{"op":"rekey"}`,
		ResultPrefix + `{"op":"rekey","nonce":"` + nonce + `","keys_base64":["` + strings.Repeat("A", MaxResultLine) + `"]}`,
	}
	for _, b := range bad {
		if _, err := FindResult([]byte(b)); err == nil {
			t.Errorf("accepted %.80q", b)
		}
	}
}

func TestCompletionChecks(t *testing.T) {
	good := &vaultclient.GenerateRootStatus{Complete: true, Nonce: nonce, PGPFingerprint: op, EncodedToken: "QUJD"}
	if _, err := GenerateRootResult(good, nonce, op); err != nil {
		t.Fatal(err)
	}
	for name, st := range map[string]*vaultclient.GenerateRootStatus{
		"not complete": {Nonce: nonce, PGPFingerprint: op, EncodedToken: "QUJD"},
		"other nonce":  {Complete: true, Nonce: "00000000-0000-0000-0000-000000000000", PGPFingerprint: op, EncodedToken: "QUJD"},
		"no nonce":     {Complete: true, PGPFingerprint: op, EncodedToken: "QUJD"},
		"unpinned key": {Complete: true, Nonce: nonce, PGPFingerprint: off, EncodedToken: "QUJD"},
		"empty token":  {Complete: true, Nonce: nonce, PGPFingerprint: op},
		"not base64":   {Complete: true, Nonce: nonce, PGPFingerprint: op, EncodedToken: "hvs.not-encrypted!"},
	} {
		if _, err := GenerateRootResult(st, nonce, op); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	fps := []string{op, op, op, op, off}
	keys := []string{"QQ==", "Qg==", "Qw==", "RA==", "RQ=="}
	vn := "06060562-47e1-7466-8d71-0b566fdcb424"
	ok := func() *vaultclient.RekeyStatus {
		return &vaultclient.RekeyStatus{Complete: true, Nonce: nonce, PGPFingerprints: append([]string(nil), fps...), KeysBase64: keys,
			VerificationRequired: true, VerificationNonce: vn}
	}
	if _, err := RekeyResult(ok(), nonce, op, off); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*vaultclient.RekeyStatus){
		"4 shares":          func(s *vaultclient.RekeyStatus) { s.KeysBase64 = keys[:4] },
		"no verification":   func(s *vaultclient.RekeyStatus) { s.VerificationRequired = false },
		"no verify nonce":   func(s *vaultclient.RekeyStatus) { s.VerificationNonce = "" },
		"offline in slot 1": func(s *vaultclient.RekeyStatus) { s.PGPFingerprints[0], s.PGPFingerprints[4] = off, op },
		"all operator":      func(s *vaultclient.RekeyStatus) { s.PGPFingerprints[4] = op },
		"other nonce":       func(s *vaultclient.RekeyStatus) { s.Nonce = vn },
	} {
		st := ok()
		mut(st)
		if _, err := RekeyResult(st, nonce, op, off); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckRekeyRequiresVerificationAndExactLayout(t *testing.T) {
	good := func() *vaultclient.RekeyStatus {
		return &vaultclient.RekeyStatus{Started: true, Nonce: nonce, Shares: 5, Threshold: 3, VerificationRequired: true,
			PGPFingerprints: []string{op, op, op, op, off}}
	}
	if err := CheckRekey(good(), op, off); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*vaultclient.RekeyStatus){
		"verification off":   func(s *vaultclient.RekeyStatus) { s.VerificationRequired = false },
		"already collected":  func(s *vaultclient.RekeyStatus) { s.VerificationNonce = nonce },
		"swapped order":      func(s *vaultclient.RekeyStatus) { s.PGPFingerprints = []string{off, op, op, op, op} },
		"offline everywhere": func(s *vaultclient.RekeyStatus) { s.PGPFingerprints = []string{off, off, off, off, off} },
	} {
		st := good()
		mut(st)
		if err := CheckRekey(st, op, off); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckRekey(good(), op, ""); !errors.Is(err, ErrRefused) {
		t.Error("missing offline pin accepted")
	}
}

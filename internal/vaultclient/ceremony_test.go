package vaultclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const testNonce = "f4fef122-4056-7c7a-0a6d-37707c6a03ec"

type recorded struct {
	method, path, token string
	body                []byte
}

func recordingVault(t *testing.T, reply string) (*Client, *[]recorded) {
	t.Helper()
	var got []recorded
	srv, ca := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, recorded{r.Method, r.URL.Path, r.Header.Get("X-Vault-Token"), b})
		if reply == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		io.WriteString(w, reply)
	}))
	c, err := New(Config{Address: srv.URL, CACertPath: ca})
	if err != nil {
		t.Fatal(err)
	}
	return c, &got
}

// The update body must carry both the share and the attempt nonce, as valid
// JSON, with awkward share bytes escaped.
func TestSubmitGenerateRootShareMarshalsKeyAndNonce(t *testing.T) {
	c, got := recordingVault(t, `{"started":true,"nonce":"`+testNonce+`","progress":1,"required":3}`)
	share := []byte(`ab"c\d`)
	st, err := c.SubmitGenerateRootShare(context.Background(), share, testNonce)
	if err != nil {
		t.Fatal(err)
	}
	if st.Progress != 1 || st.Nonce != testNonce {
		t.Fatalf("status %+v", st)
	}
	r := (*got)[0]
	if r.method != http.MethodPut || r.path != "/v1/sys/generate-root/update" {
		t.Fatalf("request %s %s", r.method, r.path)
	}
	var body map[string]string
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["key"] != string(share) || body["nonce"] != testNonce || len(body) != 2 {
		t.Fatalf("body %v", body)
	}
}

func TestSubmitRekeyShareMarshalsKeyAndNonce(t *testing.T) {
	c, got := recordingVault(t, `{"started":true,"nonce":"`+testNonce+`","t":3,"n":5,"progress":1}`)
	if _, err := c.SubmitRekeyShare(context.Background(), []byte("share-1"), testNonce); err != nil {
		t.Fatal(err)
	}
	r := (*got)[0]
	if r.path != "/v1/sys/rekey/update" || !strings.Contains(string(r.body), `"nonce":"`+testNonce+`"`) {
		t.Fatalf("request %s %s", r.path, r.body)
	}
}

// Negative: no share is sent without a well-formed nonce (an empty nonce
// would let the share land in whatever attempt is current), nor an empty share.
func TestSubmitShareRejectsBadNonceOrEmptyShare(t *testing.T) {
	c, got := recordingVault(t, `{}`)
	for name, nonce := range map[string]string{
		"empty":     "",
		"uppercase": strings.ToUpper(testNonce),
		"injection": `f4fef122-4056-7c7a-0a6d-37707c6a03e"`,
		"short":     testNonce[:35],
	} {
		if _, err := c.SubmitGenerateRootShare(context.Background(), []byte("s"), nonce); err == nil {
			t.Fatalf("%s nonce accepted", name)
		}
		if _, err := c.SubmitRekeyShare(context.Background(), []byte("s"), nonce); err == nil {
			t.Fatalf("%s nonce accepted for rekey", name)
		}
	}
	if _, err := c.SubmitGenerateRootShare(context.Background(), nil, testNonce); err == nil {
		t.Fatal("empty share accepted")
	}
	if len(*got) != 0 {
		t.Fatalf("%d requests reached Vault", len(*got))
	}
}

// Negative: there is no way to start an OTP attempt through this client.
func TestStartGenerateRootRequiresPGPKey(t *testing.T) {
	c, got := recordingVault(t, `{}`)
	if _, err := c.StartGenerateRoot(context.Background(), ""); err == nil {
		t.Fatal("OTP-style start accepted")
	}
	if len(*got) != 0 {
		t.Fatal("request reached Vault")
	}
	if _, err := c.StartGenerateRoot(context.Background(), "a2V5"); err != nil {
		t.Fatal(err)
	}
	var body map[string]string
	_ = json.Unmarshal((*got)[0].body, &body)
	if body["pgp_key"] != "a2V5" || len(body) != 1 {
		t.Fatalf("body %v", body)
	}
}

func TestStartRekeyMarshalling(t *testing.T) {
	c, got := recordingVault(t, `{"started":true,"t":3,"n":5}`)
	if _, err := c.StartRekey(context.Background(), 5, 3, []string{"a", "b"}); err == nil {
		t.Fatal("key count mismatch accepted")
	}
	keys := []string{"k1", "k2", "k3", "k4", "k5"}
	if _, err := c.StartRekey(context.Background(), 5, 3, keys); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Shares    int      `json:"secret_shares"`
		Threshold int      `json:"secret_threshold"`
		PGPKeys   []string `json:"pgp_keys"`
		Backup    bool     `json:"backup"`
		Verify    bool     `json:"require_verification"`
	}
	if err := json.Unmarshal((*got)[0].body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Shares != 5 || body.Threshold != 3 || len(body.PGPKeys) != 5 || body.Backup || !body.Verify {
		t.Fatalf("body %+v", body)
	}
}

// The OTP is never decoded, so it cannot leak through this package.
func TestGenerateRootStatusIgnoresOTP(t *testing.T) {
	c, _ := recordingVault(t, `{"started":true,"nonce":"`+testNonce+`","otp":"secret-otp-value","otp_length":28}`)
	st, err := c.GenerateRootAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(jsonString(t, st)), "secret-otp-value") {
		t.Fatal("OTP was decoded into the status")
	}
}

func jsonString(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTokenHeaderAndNoContent(t *testing.T) {
	c, got := recordingVault(t, "")
	if err := c.RevokeSelf(context.Background(), []byte("hvs.test-token")); err != nil {
		t.Fatal(err)
	}
	if (*got)[0].token != "hvs.test-token" || (*got)[0].path != "/v1/auth/token/revoke-self" {
		t.Fatalf("request %+v", (*got)[0])
	}
	// Negative: header-injection and empty tokens never reach the wire.
	for _, bad := range [][]byte{nil, {}, []byte("tok\r\nX-Evil: 1"), []byte("tok en")} {
		if bad == nil {
			continue // nil means "no token" for unauthenticated endpoints
		}
		if err := c.RevokeSelf(context.Background(), bad); err == nil {
			t.Fatalf("token %q accepted", bad)
		}
	}
	if len(*got) != 1 {
		t.Fatalf("%d requests, want 1", len(*got))
	}
}

func TestRevokedLookupIs403APIError(t *testing.T) {
	srv, ca := newTestVault(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"errors":["permission denied"]}`)
	}))
	c, _ := New(Config{Address: srv.URL, CACertPath: ca})
	_, err := c.LookupSelf(context.Background(), []byte("hvs.gone"))
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), "hvs.gone") {
		t.Fatal("token appears in error")
	}
}

func TestAppRoleLoginReturnsWipeableToken(t *testing.T) {
	c, got := recordingVault(t, `{"auth":{"client_token":"hvs.approle-token"}}`)
	tok, err := c.AppRoleLogin(context.Background(), "approle", "role-1", []byte("secret-1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(tok) != "hvs.approle-token" {
		t.Fatalf("token %q", tok)
	}
	var body map[string]string
	if err := json.Unmarshal((*got)[0].body, &body); err != nil || body["secret_id"] != "secret-1" || body["role_id"] != "role-1" {
		t.Fatalf("body %s (%v)", (*got)[0].body, err)
	}
	if _, err := c.AppRoleLogin(context.Background(), "approle", "role-1", []byte(`se"cret`)); err == nil {
		t.Fatal("unescaped quote in secret_id accepted")
	}
}

func TestRekeyVerifyMarshalling(t *testing.T) {
	c, got := recordingVault(t, `{"started":true,"nonce":"`+testNonce+`","progress":1}`)
	st, err := c.SubmitRekeyVerifyShare(context.Background(), []byte("new-share-1"), testNonce)
	if err != nil || st.Progress != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	r := (*got)[0]
	var body map[string]string
	if err := json.Unmarshal(r.body, &body); err != nil || r.path != "/v1/sys/rekey/verify" || r.method != http.MethodPut ||
		body["key"] != "new-share-1" || body["nonce"] != testNonce {
		t.Fatalf("%s %s %s", r.method, r.path, r.body)
	}
	if _, err := c.SubmitRekeyVerifyShare(context.Background(), []byte("x"), ""); err == nil {
		t.Fatal("verify share without nonce accepted")
	}
}

func TestTokenInfoDecodesFreshnessFields(t *testing.T) {
	c, _ := recordingVault(t, `{"data":{"accessor":"a","policies":["root"],"ttl":0,"expire_time":null,"creation_time":1791313950,"path":"auth/token/root"}}`)
	ti, err := c.LookupSelf(context.Background(), []byte("hvs.x"))
	if err != nil {
		t.Fatal(err)
	}
	if ti.ExpireTime != nil || ti.CreationTime != 1791313950 || ti.Path != "auth/token/root" {
		t.Fatalf("%+v", ti)
	}
}

// Current Vault releases require the rekey nonce to cancel; a cancel can
// only ever name the attempt the caller validated.
func TestCancelRekeySendsNonce(t *testing.T) {
	c, got := recordingVault(t, "")
	if err := c.CancelRekey(context.Background(), nil, testNonce); err != nil {
		t.Fatal(err)
	}
	r := (*got)[0]
	if r.method != http.MethodDelete || r.path != "/v1/sys/rekey/init" || string(r.body) != `{"nonce":"`+testNonce+`"}` {
		t.Fatalf("%s %s %s", r.method, r.path, r.body)
	}
	if err := c.CancelRekey(context.Background(), nil, ""); err == nil || len(*got) != 1 {
		t.Fatal("cancel without a nonce accepted")
	}
}

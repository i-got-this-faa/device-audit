package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

type fakeIssuer struct {
	server       *httptest.Server
	key          *rsa.PrivateKey
	clientID     string
	clientSecret string

	mu               sync.Mutex
	subject          string
	amr              []string
	authTimeOverride *int64
	nonceOverride    string
	codes            map[string]fakeAuthorizationCode
	lastCode         string
	lastIDToken      string
}

type fakeAuthorizationCode struct {
	subject     string
	nonce       string
	challenge   string
	redirectURI string
	used        bool
}

func newFakeIssuer(t *testing.T, clientID, clientSecret string) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &fakeIssuer{
		key:          key,
		clientID:     clientID,
		clientSecret: clientSecret,
		subject:      "subject-viewer",
		amr:          []string{"pwd", "mfa"},
		codes:        make(map[string]fakeAuthorizationCode),
	}
	issuer.server = httptest.NewTLSServer(http.HandlerFunc(issuer.handle))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (f *fakeIssuer) URL() string {
	return f.server.URL
}

func (f *fakeIssuer) SetSubject(subject string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subject = subject
}

func (f *fakeIssuer) SetAMR(amr ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.amr = amr
}

func (f *fakeIssuer) SetNonceOverride(nonce string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonceOverride = nonce
}

func (f *fakeIssuer) LastCode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastCode
}

func (f *fakeIssuer) LastIDToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastIDToken
}

func (f *fakeIssuer) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                f.server.URL,
			"authorization_endpoint":                f.server.URL + "/authorize",
			"token_endpoint":                        f.server.URL + "/token",
			"jwks_uri":                              f.server.URL + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	case "/keys":
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes()),
		}}})
	case "/authorize":
		f.authorize(w, r)
	case "/token":
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIssuer) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("max_age") != "0" || query.Get("response_type") != "code" ||
		query.Get("client_id") != f.clientID ||
		query.Get("code_challenge_method") != "S256" ||
		query.Get("code_challenge") == "" ||
		query.Get("nonce") == "" ||
		query.Get("redirect_uri") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	code, err := randomToken(24)
	if err != nil {
		http.Error(w, "generate code", http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	subject := f.subject
	if hint := query.Get("login_hint"); hint != "" {
		subject = hint
	}
	f.codes[code] = fakeAuthorizationCode{
		subject:     subject,
		nonce:       query.Get("nonce"),
		challenge:   query.Get("code_challenge"),
		redirectURI: query.Get("redirect_uri"),
	}
	f.lastCode = code
	f.mu.Unlock()

	redirect, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (f *fakeIssuer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid token form", http.StatusBadRequest)
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.PostForm.Get("client_id")
		clientSecret = r.PostForm.Get("client_secret")
	}
	if clientID != f.clientID || clientSecret != f.clientSecret {
		http.Error(w, "invalid client", http.StatusUnauthorized)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		http.Error(w, "invalid grant", http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	f.mu.Lock()
	entry, found := f.codes[code]
	alreadyUsed := found && entry.used
	f.mu.Unlock()
	if !found || alreadyUsed || entry.redirectURI != r.PostForm.Get("redirect_uri") {
		http.Error(w, fmt.Sprintf("invalid code found=%v used=%v redirect=%q request=%q code=%q", found, alreadyUsed, entry.redirectURI, r.PostForm.Get("redirect_uri"), code), http.StatusBadRequest)
		return
	}
	verifier := r.PostForm.Get("code_verifier")
	if verifier == "" {
		http.Error(w, "missing code verifier", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != entry.challenge {
		http.Error(w, "invalid code verifier", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	entry = f.codes[code]
	if entry.used {
		f.mu.Unlock()
		http.Error(w, "invalid code reused", http.StatusBadRequest)
		return
	}
	entry.used = true
	f.codes[code] = entry
	f.mu.Unlock()
	f.mu.Lock()
	amr := append([]string(nil), f.amr...)
	nonce := entry.nonce
	if f.nonceOverride != "" {
		nonce = f.nonceOverride
	}
	f.mu.Unlock()
	idToken, err := f.signIDToken(entry.subject, nonce, amr)
	if err != nil {
		http.Error(w, "sign ID token", http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	f.lastIDToken = idToken
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (f *fakeIssuer) signIDToken(subject, nonce string, amr []string) (string, error) {
	header := map[string]any{"alg": "RS256", "kid": "test-key", "typ": "JWT"}
	now := time.Now()
	claims := map[string]any{
		"iss":       f.server.URL,
		"sub":       subject,
		"aud":       f.clientID,
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"nonce":     nonce,
		"amr":       amr,
	}
	f.mu.Lock()
	if f.authTimeOverride != nil {
		claims["auth_time"] = *f.authTimeOverride
	}
	f.mu.Unlock()
	encodedHeader, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + base64.RawURLEncoding.EncodeToString(encodedClaims)
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

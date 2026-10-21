package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is the verified subset of an ID token used for local authorization.
// Email, group and tenant claims are deliberately not part of this boundary.
type Identity struct {
	Issuer          string
	Subject         string
	Nonce           string
	AuthenticatedAt time.Time
	AMR             []string
}

type IdentityProvider interface {
	AuthCodeURL(ctx context.Context, state, nonce, codeVerifier string) (string, error)
	Exchange(ctx context.Context, code, codeVerifier string) (Identity, error)
}

// OIDCProvider discovers one operator-configured issuer lazily. A transient
// discovery failure fails new logins closed while existing local sessions stay
// usable until their normal expiry or revocation.
type OIDCProvider struct {
	issuerURL    string
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewOIDCProvider(issuerURL, clientID, clientSecret, redirectURL string, httpClient *http.Client) *OIDCProvider {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &OIDCProvider{
		issuerURL:    issuerURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		httpClient:   httpClient,
	}
}

func (p *OIDCProvider) ensure(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return nil
	}
	discoveryContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if p.httpClient != nil {
		discoveryContext = oidc.ClientContext(discoveryContext, p.httpClient)
	}
	provider, err := oidc.NewProvider(discoveryContext, p.issuerURL)
	if err != nil {
		return fmt.Errorf("discover OIDC issuer: %w", err)
	}
	if provider.Endpoint().AuthURL == "" || provider.Endpoint().TokenURL == "" {
		return errors.New("OIDC issuer did not publish authorization and token endpoints")
	}
	p.provider = provider
	p.config = oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: p.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}
	p.verifier = provider.Verifier(&oidc.Config{ClientID: p.clientID})
	return nil
}

func (p *OIDCProvider) AuthCodeURL(ctx context.Context, state, nonce, codeVerifier string) (string, error) {
	if err := p.ensure(ctx); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.config.AuthCodeURL(state,
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("max_age", "0"),
	), nil
}

func (p *OIDCProvider) Exchange(ctx context.Context, code, codeVerifier string) (Identity, error) {
	if err := p.ensure(ctx); err != nil {
		return Identity{}, err
	}
	p.mu.Lock()
	config := p.config
	verifier := p.verifier
	httpClient := p.httpClient
	p.mu.Unlock()
	if httpClient != nil {
		ctx = oidc.ClientContext(ctx, httpClient)
	}

	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Identity{}, errors.New("token response did not include an ID token")
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify ID token: %w", err)
	}
	var claims struct {
		AMR      []string `json:"amr"`
		AuthTime int64    `json:"auth_time"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read ID token claims: %w", err)
	}
	return Identity{
		Issuer:          idToken.Issuer,
		Subject:         idToken.Subject,
		Nonce:           idToken.Nonce,
		AMR:             claims.AMR,
		AuthenticatedAt: time.Unix(claims.AuthTime, 0).UTC(),
	}, nil
}

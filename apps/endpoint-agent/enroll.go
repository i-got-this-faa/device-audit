package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"golang.org/x/crypto/nacl/box"
)

func enrollmentClient(origin, caFile string) (*http.Client, string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, "", errors.New("enrollment requires a trusted HTTPS origin")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, "", errors.New("read enrollment CA")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, "", errors.New("invalid enrollment CA")
		}
		config.RootCAs = pool
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: config}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, "https://" + u.Host, nil
}

func readBootstrap(r io.Reader) (contracts.BootstrapTokenV1, error) {
	var token contracts.BootstrapTokenV1
	data, err := io.ReadAll(io.LimitReader(r, 16385))
	if err != nil || len(data) > 16384 {
		return token, errors.New("read bootstrap credential")
	}
	defer clear(data)
	if json.Unmarshal(data, &token) != nil || token.Validate() != nil {
		return token, errors.New("invalid bootstrap credential")
	}
	expires, _ := time.Parse(time.RFC3339, token.ExpiresAt)
	if !expires.After(time.Now()) {
		return token, errors.New("bootstrap credential expired")
	}
	return token, nil
}

func postEnrollment(ctx context.Context, client *http.Client, endpoint, token string, status int, input, output interface{ Validate() error }) error {
	data, err := json.Marshal(input)
	if err != nil {
		return errors.New("encode enrollment request")
	}
	// net/http may finish reading a request body after Do returns. Do not
	// overwrite its backing bytes while the transport still owns the body.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return errors.New("create enrollment request")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return errors.New("enrollment transport failed; admission may be uncertain")
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		if response.StatusCode >= http.StatusInternalServerError {
			return errors.New("enrollment server error; admission may be uncertain; preserve identity and reconcile with operator")
		}
		return errors.New("enrollment rejected; retained identity is unchanged")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	defer clear(body)
	if err != nil || len(body) > 16384 || json.Unmarshal(body, output) != nil || output.Validate() != nil {
		return errors.New("invalid enrollment response; admission may be uncertain")
	}
	return nil
}

func enroll(ctx context.Context, s *identityStore, client *http.Client, origin string, token contracts.BootstrapTokenV1) (contracts.EnrollmentAcceptedV1, error) {
	var accepted contracts.EnrollmentAcceptedV1
	_, keyErr := s.root.Lstat(keyFile)
	_, scopeErr := s.root.Lstat("scope.json")
	if (keyErr == nil) != (scopeErr == nil) {
		return accepted, errors.New("incomplete identity provisioning; preserve state for operator recovery")
	}
	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return accepted, errors.New("inspect identity keys")
	}
	if scopeErr != nil && !errors.Is(scopeErr, os.ErrNotExist) {
		return accepted, errors.New("inspect identity scope")
	}
	i, err := s.load(true)
	if err != nil {
		return accepted, err
	}
	start := i.start(token.DeploymentID, token.DeviceID)
	if err := start.Validate(); err != nil {
		return accepted, errors.New("invalid enrollment scope")
	}
	if receipt, err := s.receipt(i, token.DeploymentID, token.DeviceID); err == nil {
		return receipt, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return accepted, err
	}
	// Pin pending keys to scope before sending either proof. This file is immutable.
	scope, _ := json.Marshal(start)
	if existing, err := s.read("scope.json"); errors.Is(err, os.ErrNotExist) {
		if err := s.write("scope.json", scope); err != nil {
			return accepted, err
		}
	} else if err != nil || !bytes.Equal(existing, scope) {
		return accepted, errors.New("pending identity has another scope or damaged state")
	}
	var challenge contracts.EnrollmentChallengeV1
	if err := postEnrollment(ctx, client, origin+"/v1/enrollment/challenges", token.Token, http.StatusOK, start, &challenge); err != nil {
		return accepted, err
	}
	admission, err := i.admission(start, challenge, token.ExpiresAt, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return accepted, err
	}
	if err := postEnrollment(ctx, client, origin+"/v1/enrollment", token.Token, http.StatusCreated, admission, &accepted); err != nil {
		return accepted, err
	}
	if err := verifyAcceptance(accepted, start); err != nil {
		return accepted, err
	}
	// Sequence state precedes the receipt: an admitted identity can never
	// sign evidence from a silently reset high-water mark.
	if err := s.initSequence(accepted); err != nil {
		return accepted, errors.New("admission may have committed but sequence state was not saved; keep identity and reconcile with operator")
	}
	data, _ := json.Marshal(accepted)
	if err := s.write(receiptFile, data); err != nil {
		return accepted, errors.New("admission may have committed but local receipt was not saved; keep identity and reconcile with operator")
	}
	return accepted, nil
}

func (i *identity) admission(start contracts.EnrollmentStartV1, challenge contracts.EnrollmentChallengeV1, tokenExpiry string, now time.Time) (contracts.EnrollmentAdmissionV1, error) {
	var result contracts.EnrollmentAdmissionV1
	id, _ := contracts.SigningKeyIDV1(i.signing.Public().(ed25519.PublicKey))
	expires, _ := time.Parse(time.RFC3339, challenge.ExpiresAt)
	tokenExpires, _ := time.Parse(time.RFC3339, tokenExpiry)
	if challenge.Validate() != nil || challenge.DeploymentID != start.DeploymentID || challenge.DeviceID != start.DeviceID || challenge.SigningKeyID != id || challenge.NetworkPublicKey != start.NetworkPublicKey || !expires.After(now) || expires.After(tokenExpires) || expires.After(now.Add(contracts.EnrollmentMaxLifetimeV1)) {
		return result, errors.New("challenge does not match identity, scope or expiry")
	}
	sealed, _ := base64.StdEncoding.DecodeString(challenge.NetworkChallenge)
	public := [32]byte(i.network.PublicKey().Bytes())
	private := [32]byte(i.network.Bytes())
	defer clear(private[:])
	proof, ok := box.OpenAnonymous(nil, sealed, &public, &private)
	if !ok || len(proof) != 32 {
		return result, errors.New("network possession challenge failed")
	}
	defer clear(proof)
	inner := contracts.EnrollmentEnvelopeV1{EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{SchemaVersion: contracts.EnrollmentV1Version, DeploymentID: start.DeploymentID, DeviceID: start.DeviceID, SigningKeyID: id, Sequence: contracts.EnrollmentSequenceV1, IssuedAt: now.Format(time.RFC3339), ExpiresAt: challenge.ExpiresAt}, PublicKey: start.PublicKey, ChallengeID: challenge.ChallengeID}
	message, err := inner.SigningBytes()
	if err != nil {
		return result, errors.New("build enrollment proof")
	}
	inner.Signature = hex.EncodeToString(ed25519.Sign(i.signing, message))
	result = contracts.EnrollmentAdmissionV1{SchemaVersion: contracts.EnrollmentAdmissionV1Version, Enrollment: inner, NetworkPublicKey: start.NetworkPublicKey, NetworkProof: hex.EncodeToString(proof)}
	message, err = result.SigningBytes()
	if err != nil {
		return result, errors.New("build network admission proof")
	}
	result.Signature = hex.EncodeToString(ed25519.Sign(i.signing, message))
	return result, nil
}

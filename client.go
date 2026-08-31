// Package qwiktoday implements the client side of Qwik Today's OAuth device flow.
package qwiktoday

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

var ErrInvalidConfiguration = errors.New("invalid OAuth device client configuration")

type Client struct {
	BaseURL    string
	ClientID   string
	HTTPClient *http.Client
}

type Session struct {
	ClientID                string
	DeviceCode              string
	UserCode                string
	CodeVerifier            string
	VerificationURI         string
	VerificationURIComplete string
	QRPayload               string
	ExpiresAt               time.Time
	Interval                time.Duration
}

type Credential struct {
	UUID      string    `json:"uuid"`
	Key       string    `json:"key"`
	Secret    string    `json:"secret"`
	Name      string    `json:"name"`
	Scopes    []string  `json:"scopes"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type APIError struct {
	HTTPStatus  int
	Code        string
	Description string
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("OAuth device error %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("OAuth device error: %s", e.Code)
}

func (e *APIError) Pending() bool  { return e.Code == "authorization_pending" }
func (e *APIError) SlowDown() bool { return e.Code == "slow_down" }

type authorizeRequest struct {
	ClientID      string   `json:"client_id"`
	Scopes        []string `json:"scopes"`
	CodeChallenge string   `json:"code_challenge"`
}

type authorizeResponse struct {
	Message string `json:"message"`
	Data    struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		QRPayload               string `json:"qr_payload"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	} `json:"data"`
}

type errorEnvelope struct {
	Message          interface{} `json:"message"`
	Error            string      `json:"error"`
	ErrorDescription string      `json:"error_description"`
}

func New(baseURL, clientID string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	clientID = strings.TrimSpace(clientID)
	if baseURL == "" || clientID == "" {
		return nil, ErrInvalidConfiguration
	}
	return &Client{BaseURL: baseURL, ClientID: clientID, HTTPClient: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func generatePKCE() (verifier, challenge string, err error) {
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(digest[:])
	return verifier, challenge, nil
}

func (c *Client) Start(ctx context.Context, scopes ...string) (*Session, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: at least one scope is required", ErrInvalidConfiguration)
	}
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("generate PKCE: %w", err)
	}

	var response authorizeResponse
	status, raw, err := c.postJSON(ctx, "/api/v1/oauth/device/authorize", authorizeRequest{ClientID: c.ClientID, Scopes: scopes, CodeChallenge: challenge}, &response)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, decodeAPIError(status, raw)
	}
	if response.Data.DeviceCode == "" || response.Data.QRPayload == "" {
		return nil, fmt.Errorf("invalid device authorization response")
	}
	interval := time.Duration(response.Data.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	return &Session{
		ClientID: c.ClientID, DeviceCode: response.Data.DeviceCode, UserCode: response.Data.UserCode,
		CodeVerifier: verifier, VerificationURI: response.Data.VerificationURI,
		VerificationURIComplete: response.Data.VerificationURIComplete, QRPayload: response.Data.QRPayload,
		ExpiresAt: time.Now().Add(time.Duration(response.Data.ExpiresIn) * time.Second), Interval: interval,
	}, nil
}

func (c *Client) Poll(ctx context.Context, session *Session) (*Credential, error) {
	if session == nil || session.DeviceCode == "" || session.CodeVerifier == "" {
		return nil, fmt.Errorf("%w: invalid session", ErrInvalidConfiguration)
	}
	request := map[string]interface{}{"grant_type": DeviceGrantType, "client_id": session.ClientID, "device_code": session.DeviceCode, "code_verifier": session.CodeVerifier}
	var credential Credential
	status, raw, err := c.postJSON(ctx, "/api/v1/oauth/device/token", request, &credential)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, decodeAPIError(status, raw)
	}
	if credential.Key == "" || credential.Secret == "" {
		return nil, fmt.Errorf("invalid credential response")
	}
	return &credential, nil
}

// Wait polls until the member approves, denies, or the session expires.
func (c *Client) Wait(ctx context.Context, session *Session) (*Credential, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: invalid session", ErrInvalidConfiguration)
	}
	interval := session.Interval
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	for {
		if !session.ExpiresAt.IsZero() && !time.Now().Before(session.ExpiresAt) {
			return nil, &APIError{Code: "expired_token", Description: "device authorization expired"}
		}
		credential, err := c.Poll(ctx, session)
		if err == nil {
			return credential, nil
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || (!apiErr.Pending() && !apiErr.SlowDown()) {
			return nil, err
		}
		if apiErr.SlowDown() {
			interval += 5 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) postJSON(ctx context.Context, path string, body, target interface{}) (int, []byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && target != nil {
		if err := json.Unmarshal(raw, target); err != nil {
			return resp.StatusCode, raw, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, raw, nil
}

func decodeAPIError(status int, raw []byte) error {
	var envelope errorEnvelope
	_ = json.Unmarshal(raw, &envelope)
	code, description := envelope.Error, envelope.ErrorDescription
	if code == "" {
		code = http.StatusText(status)
	}
	if description == "" && envelope.Message != nil {
		description = fmt.Sprint(envelope.Message)
	}
	return &APIError{HTTPStatus: status, Code: code, Description: description}
}

package qwiktoday

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func mockClient(t *testing.T, status int, response string, inspect func(*http.Request)) *Client {
	t.Helper()

	client, err := New("https://api.example.test", "desktop-pos")
	if err != nil {
		t.Fatal(err)
	}

	client.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if inspect != nil {
			inspect(req)
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(response)),
		}, nil
	})}

	return client
}

func TestStartGeneratesValidPKCEAndSession(t *testing.T) {
	var challenge string
	client := mockClient(t, http.StatusOK,
		`{"message":"ok","data":{"device_code":"device","user_code":"ABCD-1234","verification_uri":"qwik://oauth/device","verification_uri_complete":"qwik://oauth/device?user_code=ABCD-1234","qr_payload":"qwik://oauth/device?user_code=ABCD-1234","expires_in":300,"interval":5}}`,
		func(req *http.Request) {
			if req.URL.Path != "/api/v1/oauth/device/authorize" {
				t.Errorf("path = %s", req.URL.Path)
			}
			var payload authorizeRequest
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Error(err)
				return
			}
			challenge = payload.CodeChallenge
		},
	)

	session, err := client.Start(context.Background(), "soundbox.billing")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	digest := sha256.Sum256([]byte(session.CodeVerifier))
	if got := base64.RawURLEncoding.EncodeToString(digest[:]); got != challenge {
		t.Fatalf("PKCE challenge = %q, want %q", challenge, got)
	}
	if session.QRPayload == "" || session.DeviceCode != "device" {
		t.Fatalf("unexpected session: %+v", session)
	}
}

func TestPollParsesPendingError(t *testing.T) {
	client := mockClient(t, http.StatusBadRequest, `{"error":"authorization_pending"}`, nil)

	_, err := client.Poll(context.Background(), &Session{
		ClientID:     "desktop-pos",
		DeviceCode:   "device",
		CodeVerifier: "verifier",
	})
	apiErr, ok := err.(*APIError)
	if !ok || !apiErr.Pending() {
		t.Fatalf("Poll() error = %#v", err)
	}
}

func TestPollReturnsCredential(t *testing.T) {
	client := mockClient(t, http.StatusOK,
		`{"uuid":"id","key":"key","secret":"secret","name":"POS","scopes":["soundbox.billing"],"status":"active","created_at":"2026-08-31T08:00:00Z"}`, nil)

	credential, err := client.Poll(context.Background(), &Session{
		ClientID:     "desktop-pos",
		DeviceCode:   "device",
		CodeVerifier: "verifier",
	})
	if err != nil {
		t.Fatalf("Poll() error = %v", err)
	}
	if credential.Key != "key" || credential.Secret != "secret" {
		t.Fatalf("unexpected credential: %+v", credential)
	}
}

func TestRevokeSignsCurrentCredential(t *testing.T) {
	client := mockClient(t, http.StatusOK, `{"message":"OAuth credential revoked successfully","data":null}`,
		func(req *http.Request) {
			if req.Method != http.MethodDelete || req.URL.Path != "/api/client/oauth/revoke" {
				t.Errorf("request = %s %s", req.Method, req.URL.Path)
			}
			bodyHash := sha256.Sum256([]byte("{}"))
			stringToSign := req.Method + ":key:" + hex.EncodeToString(bodyHash[:]) + ":secret"
			mac := hmac.New(sha256.New, []byte("secret"))
			_, _ = mac.Write([]byte(stringToSign))
			if got, want := req.Header.Get("signature"), hex.EncodeToString(mac.Sum(nil)); got != want {
				t.Errorf("signature = %q, want %q", got, want)
			}
			if got := req.Header.Get("va"); got != "key" {
				t.Errorf("va = %q", got)
			}
		},
	)

	if err := client.Revoke(context.Background(), "key", "secret"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
}

func TestRevokeRequiresCredential(t *testing.T) {
	client, err := New("https://api.example.test", "desktop-pos")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(context.Background(), "", ""); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("Revoke() error = %v", err)
	}
}

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

func TestListSoundboxUsers(t *testing.T) {
	client := mockClient(t, http.StatusOK, `{"message":"ok","data":[{"id":1,"uuid":"su-1","is_active":true,"outstanding_billing":3000}],"pagination":{"page":1,"limit":10,"total":1,"total_page":1}}`, func(req *http.Request) {
		if req.URL.Path != "/api/client/soundbox-user" || req.URL.Query().Get("page") != "1" {
			t.Errorf("unexpected URL: %s", req.URL.String())
		}
		if req.Header.Get("va") != "key" || req.Header.Get("signature") == "" {
			t.Error("signed headers are missing")
		}
	})
	items, pagination, err := client.ListSoundboxUsers(context.Background(), "key", "secret", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].UUID != "su-1" || pagination.Total != 1 {
		t.Fatalf("unexpected response: %+v %+v", items, pagination)
	}
}

func TestSendSoundboxNotificationSignsExactBody(t *testing.T) {
	payload := SoundboxNotificationRequest{Amount: "10000"}
	client := mockClient(t, http.StatusOK, `{"message":"ok","data":{"status":200}}`, func(req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		stringToSign := req.Method + ":key:" + hex.EncodeToString(digest[:]) + ":secret"
		mac := hmac.New(sha256.New, []byte("secret"))
		_, _ = mac.Write([]byte(stringToSign))
		if req.Header.Get("signature") != hex.EncodeToString(mac.Sum(nil)) {
			t.Error("signature does not match request body")
		}
	})
	response, err := client.SendSoundboxNotification(context.Background(), "key", "secret", "su-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if response["status"] != float64(200) {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestPayBillings(t *testing.T) {
	client := mockClient(t, http.StatusOK, `{"message":"ok","data":{"uuid":"pay-1","amount":6000,"status":"pending","payment_method":"qris","payment_url":"https://payment.test/pay-1","expires_at":"2026-09-03T11:00:00+08:00"}}`, func(req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/api/client/billings/payment" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		var payload BillingPaymentRequest
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if len(payload.BillingUUIDs) != 2 || payload.PaymentMethod != "qris" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	})
	payment, err := client.PayBillings(context.Background(), "key", "secret", BillingPaymentRequest{
		BillingUUIDs: []string{"billing-1", "billing-2"}, PaymentMethod: "qris",
	})
	if err != nil {
		t.Fatal(err)
	}
	if payment.UUID != "pay-1" || payment.Amount != 6000 || payment.PaymentURL == "" {
		t.Fatalf("unexpected response: %+v", payment)
	}
}

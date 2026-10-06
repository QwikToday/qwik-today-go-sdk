# Qwik Today Client for Go

```go
client, err := qwiktoday.New("https://api.example.com", "desktop-pos")
if err != nil {
	log.Fatal(err)
}

session, err := client.Start(
	context.Background(),
	"client.test",
	"soundbox-user.read",
	"soundbox-billing.read",
	"soundbox-billing.pay",
	"soundbox-notification.create",
)
if err != nil {
	log.Fatal(err)
}

// Render session.QRPayload with the QR library used by your application.
fmt.Println(session.QRPayload)

credential, err := client.Wait(context.Background(), session)
if err != nil {
	log.Fatal(err)
}

// Store these values in the operating system's secure credential storage.
fmt.Println(credential.Key, credential.Secret)

// Load the key and secret from secure storage when access must be revoked.
if err := client.Revoke(context.Background(), credential.Key, credential.Secret); err != nil {
	log.Fatal(err)
}

// Delete the local key and secret only after Revoke returns nil.
```

The package uses only the Go standard library. `device_code`, `code_verifier`,
and the issued secret are sensitive and must not be logged or embedded in the QR.
The SDK never persists credentials. Secure storage and credential lifecycle on
the device remain the responsibility of the client application.

## Client API

### Supported scopes

| Scope | Endpoint | Description |
|---|---|---|
| `client.test` | `GET /api/client/test` | Test the client credential and request signature, including granted scopes. |
| `qris-static.read` | `GET /api/client/qris-static` | List QRIS static owned by the credential user. |
| `qris-static.read` | `GET /api/client/qris-static/:nmid` | Get one owned QRIS static by NMID. |
| `qris-static.webhook.read` | `GET /api/client/qris-static/:nmid/webhooks` | List webhook URLs for an owned QRIS. |
| `qris-static.webhook.manage` | `POST /api/client/qris-static/:nmid/webhooks` | Add a webhook URL to an owned QRIS. |
| `qris-static.webhook.manage` | `DELETE /api/client/qris-static/:nmid/webhooks/:id` | Remove a webhook URL from an owned QRIS. |
| `qris-static.notification.create` | `POST /api/client/qris-static/:nmid/notification` | Send a non-persistent test notification to all active webhooks. |
| `soundbox-user.read` | `GET /api/client/soundbox-user` | List the member's soundbox users. |
| `soundbox-user.read` | `GET /api/client/soundbox-user/:uuid` | Get a soundbox user, including its TSM device data. |
| `soundbox-billing.read` | `GET /api/client/billings` | List billings from all soundboxes owned by the member. |
| `soundbox-billing.pay` | `POST /api/client/billings/payment` | Create or reuse an active iPaymu payment link for selected billings. |
| `soundbox-notification.create` | `POST /api/client/soundbox-user/:soundbox_user_uuid/notification` | Send a transaction notification to TSM and trigger daily pay-as-you-go billing. |

`DELETE /api/client/oauth/revoke` does not require an additional scope. It
still requires a valid signed OAuth credential, because a credential must
always be able to revoke itself.

An OAuth credential can only receive scopes that are included in the OAuth
client's `allowed_scopes`, requested during device authorization, and approved
by the member. Legacy credentials without an OAuth client ID bypass scope
checks for backward compatibility, but must still be active, unexpired, and
correctly signed.

After authorization, use the returned key and secret:

```go
soundboxes, pagination, err := client.ListSoundboxUsers(ctx, credential.Key, credential.Secret, 1, 10)
detail, err := client.GetSoundboxUser(ctx, credential.Key, credential.Secret, soundboxes[0].UUID)
billings, err := client.ListBillings(ctx, credential.Key, credential.Secret, "unpaid")
payment, err := client.PayBillings(ctx, credential.Key, credential.Secret, qwiktoday.BillingPaymentRequest{
	BillingUUIDs: []string{billings.Billings[0].UUID},
	PaymentMethod: "qris",
})
response, err := client.SendSoundboxNotification(ctx, credential.Key, credential.Secret, detail.UUID, qwiktoday.SoundboxNotificationRequest{
	Amount: "150000.00",
})

qris, err := client.ListQrisStatics(ctx, credential.Key, credential.Secret)
webhook, err := client.AddQrisWebhook(ctx, credential.Key, credential.Secret, qris[0].Nmid, qwiktoday.QrisStaticWebhookRequest{
	URL: "https://partner.example/webhooks/qris",
})
testResult, err := client.TestQrisStaticNotification(ctx, credential.Key, credential.Secret, qris[0].Nmid)
fmt.Println(webhook.ID, testResult.Webhooks)
```

### Webhook payload and security

The webhook body is intentionally minimal:

```json
{"total":0}
```

For a real payment, `total` contains the payment total. The event type is sent
in the `X-Qwik-Event` header (`qris.static.payment` for a real payment and
`qris.static.test` for a test). If a webhook secret is configured, Qwik sends
the hexadecimal HMAC-SHA256 digest in `X-Qwik-Signature`.

Verify the signature against the exact raw request bytes before parsing JSON:

```go
rawBody, err := io.ReadAll(r.Body)
if err != nil || !qwiktoday.VerifyQrisWebhookSignature(
	rawBody,
	r.Header.Get("X-Qwik-Signature"),
) {
	http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
	return
}

var payload qwiktoday.QrisStaticWebhookPayload
if err := json.Unmarshal(rawBody, &payload); err != nil {
	http.Error(w, "invalid webhook payload", http.StatusBadRequest)
	return
}
```

Security recommendations:

- Use an HTTPS webhook URL and validate the URL before registering it.
- Generate a random secret of at least 32 bytes; do not use a predictable name,
  NMID, API key, or password.
- Store the secret in a secret manager or encrypted environment variable. The
  API never returns it when listing webhooks.
- Never log the secret, signature, or raw body if it can contain sensitive data.
- Compare signatures with the SDK helper, which uses constant-time comparison.
- Keep the raw body unchanged until signature verification is complete; even
  whitespace or re-serialization changes the signature input.
- Return a 2xx response only after accepting the notification. Use an
  idempotency key in the receiving application if duplicate delivery handling
  is required.
- Rotate a secret by registering a new webhook with the new secret, verifying
  it, then deleting the old webhook.

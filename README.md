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
| `client.test` | `POST /api/client/test` | Test the client credential and request signature. |
| `soundbox-user.read` | `GET /api/client/soundbox-user` | List the member's soundbox users. |
| `soundbox-user.read` | `GET /api/client/soundbox-user/:uuid` | Get a soundbox user, including its TSM device data. |
| `soundbox-billing.read` | `GET /api/client/billings` | List billings from all soundboxes owned by the member. |
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
response, err := client.SendSoundboxNotification(ctx, credential.Key, credential.Secret, detail.UUID, qwiktoday.SoundboxNotificationRequest{
	Amount: "150000.00", BillNumber: "INV-001", IssuerCode: "93600911", PaymentStatus: "SUCCESS",
})
```

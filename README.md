# Qwik Today Client for Go

```go
client, err := qwiktoday.New("https://api.example.com", "desktop-pos")
if err != nil {
	log.Fatal(err)
}

session, err := client.Start(context.Background(), "soundbox.billing")
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

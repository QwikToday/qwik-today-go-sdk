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
```

The package uses only the Go standard library. `device_code`, `code_verifier`,
and the issued secret are sensitive and must not be logged or embedded in the QR.

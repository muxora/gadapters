# gadapters

[![Go Reference](https://pkg.go.dev/badge/github.com/muxora/gadapters.svg)](https://pkg.go.dev/github.com/muxora/gadapters)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Payment gateway adapters for Go. One small interface, many Southeast Asian providers.

## Features

- Single `Provider` interface: create checkout, fetch payment, validate webhook
- Zero third-party runtime dependencies (stdlib only)
- Functional options: custom base URL (sandbox), `*http.Client`, timeout, `*slog.Logger`
- Webhook signature verification built in

## Supported providers

| Provider  | Package                                   | Region    | Webhook verification                    |
|-----------|-------------------------------------------|-----------|-----------------------------------------|
| Billplz   | `github.com/muxora/gadapters/billplz`     | Malaysia  | X Signature (HMAC-SHA256)               |
| senangPay | `github.com/muxora/gadapters/senangpay`   | Malaysia  | Hash (HMAC-SHA256)                      |
| iPaymu    | `github.com/muxora/gadapters/ipaymu`      | Indonesia | Server-to-server re-query (unsigned)    |

## Installation

```sh
go get github.com/muxora/gadapters
```

Requires Go 1.24+.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/muxora/gadapters"
	"github.com/muxora/gadapters/billplz"
)

func main() {
	var p gadapters.Provider = billplz.New(billplz.Config{
		CollectionID:  "your-collection-id",
		SecretKey:     "your-secret-key",
		XSignatureKey: "your-x-signature-key",
		CallbackURL:   "https://example.com/webhooks/billplz",
		RedirectURL:   "https://example.com/thanks",
	}, billplz.WithBaseURL("https://www.billplz-sandbox.com/api")) // omit for production

	ctx := context.Background()

	// 1. Create a checkout and redirect the payer to PaymentURL.
	res, err := p.GenerateCheckoutURL(ctx, &gadapters.CheckoutRequest{
		ReferenceID: "order-123",
		Name:        "Jane Doe",
		Email:       "jane@example.com",
		Description: "Order #123",
		Amount:      20.00,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.PaymentURL)

	// 2. In your webhook handler, verify the raw request body.
	//    id, err := p.ValidateWebhook(ctx, body)

	// 3. Fetch the authoritative payment state.
	pay, err := p.Payment(ctx, res.PaymentID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pay.Paid, pay.State, pay.Amount)
}
```

### Provider config

```go
billplz.New(billplz.Config{CollectionID, SecretKey, XSignatureKey, CallbackURL, RedirectURL})
senangpay.New(senangpay.Config{MerchantID, SecretKey})
ipaymu.New(ipaymu.Config{VA, APIKey})
```

All constructors accept the same options:

```go
WithBaseURL(url string)          // e.g. sandbox endpoint
WithHttpClient(c *http.Client)
WithTimeout(d time.Duration)
WithSlogLogger(l *slog.Logger)
```

### Provider notes

- **Billplz** — `PaymentID` is the Bill ID. `ValidateWebhook` takes the raw form-urlencoded callback body.
- **senangPay** — `PaymentID` is your `ReferenceID` (order_id). Payment is queried by order_id.
- **iPaymu** — `GenerateCheckoutURL` returns the SessionId; `Payment` expects the numeric transactionId sent to your notify URL. Notifications are unsigned, so `ValidateWebhook` re-queries iPaymu to confirm authenticity.

Amounts are always in the major currency unit (e.g. `20.00` MYR).

## Adding a provider

Implement `gadapters.Provider` in a new sub-package:

```go
type Provider interface {
	GenerateCheckoutURL(ctx context.Context, req *CheckoutRequest) (*CheckoutResponse, error)
	Payment(ctx context.Context, id string) (*Payment, error)
	ValidateWebhook(ctx context.Context, payload []byte) (string, error)
}
```

Add a compile-time check (`var _ gadapters.Provider = (*Client)(nil)`) and tests using `httptest.Server`.

## Development

```sh
go vet ./...
go test ./...
```

## Contributing

Contributions welcome.

1. Fork the repo and create a branch from `main`.
2. Add tests for your change; keep `go vet` and `go test` green.
3. Never commit real credentials — use `httptest` and dummy keys.
4. Open a pull request describing the change.

For larger changes, open an issue first to discuss.

## Security

Please do not report security vulnerabilities through public issues. Use
[GitHub private vulnerability reporting](https://github.com/muxora/gadapters/security/advisories/new) instead.

## License

[MIT](LICENSE)

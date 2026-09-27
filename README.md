# gadapters

[![Go Reference](https://pkg.go.dev/badge/github.com/muxora/gadapters.svg)](https://pkg.go.dev/github.com/muxora/gadapters)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Payment gateway adapters for Go. One small interface, many Southeast Asian providers.

## Features

- Single `Provider` interface: create checkout, fetch payment, validate webhook, plus gateway name and country
- Zero third-party runtime dependencies (stdlib only)
- Functional options: custom base URL (sandbox), `*http.Client`, timeout, `*slog.Logger`
- Webhook signature verification built in

## Supported providers

| Provider  | Package                                 | Region      | Webhook verification                 |
|-----------|-----------------------------------------|-------------|--------------------------------------|
| Billplz   | `github.com/muxora/gadapters/billplz`   | Malaysia    | X Signature (HMAC-SHA256)            |
| senangPay | `github.com/muxora/gadapters/senangpay` | Malaysia    | Hash (HMAC-SHA256)                   |
| iPaymu    | `github.com/muxora/gadapters/ipaymu`    | Indonesia   | Server-to-server re-query (unsigned) |
| HitPay    | `github.com/muxora/gadapters/hitpay`    | Singapore   | Hitpay-Signature (HMAC-SHA256)       |
| toyyibPay | `github.com/muxora/gadapters/toyyibpay` | Malaysia    | Hash (MD5)                           |
| PayMongo  | `github.com/muxora/gadapters/paymongo`  | Philippines | Paymongo-Signature (HMAC-SHA256)     |

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
		Amount:      2000, // MYR 20.00, in sen
		Currency:    "MYR",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res.PaymentURL)

	// 2. In your webhook handler, verify the incoming request.
	//    id, err := p.ValidateWebhook(ctx, r) // r is the *http.Request
	//    if errors.Is(err, gadapters.ErrInvalidSignature) { ... respond 401 ... }

	// 3. Fetch the authoritative payment state.
	pay, err := p.Payment(ctx, res.PaymentID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(pay.Paid, pay.State, pay.Amount, pay.Currency)
}
```

### Provider config

```go
billplz.New(billplz.Config{CollectionID, SecretKey, XSignatureKey, CallbackURL, RedirectURL})
senangpay.New(senangpay.Config{MerchantID, SecretKey})
ipaymu.New(ipaymu.Config{VA, APIKey})
hitpay.New(hitpay.Config{APIKey, Salt, RedirectURL})
toyyibpay.New(toyyibpay.Config{UserSecretKey, CategoryCode, CallbackURL, ReturnURL})
paymongo.New(paymongo.Config{SecretKey, WebhookSecret, PaymentMethodTypes, SuccessURL, CancelURL})
```

All constructors accept the same options:

```go
WithBaseURL(url string)          // e.g. sandbox endpoint
WithHttpClient(c *http.Client)
WithTimeout(d time.Duration)
WithSlogLogger(l *slog.Logger)
```

### Provider notes

- **Billplz** (MYR) — `PaymentID` is the Bill ID. `ValidateWebhook` expects the form-urlencoded callback POST.
- **senangPay** (MYR) — `PaymentID` is your `ReferenceID` (order_id) everywhere: checkout, `Payment`, and `ValidateWebhook`. senangPay's transaction_id is not exposed. `ValidateWebhook` accepts both the callback POST and the return-URL GET.
- **iPaymu** (IDR) — `GenerateCheckoutURL` returns the SessionId; `Payment` expects the numeric transactionId sent to your notify URL. Notifications are unsigned, so `ValidateWebhook` re-queries iPaymu to confirm authenticity. iPaymu only accepts whole rupiah, so `Amount` must be a multiple of 100.
- **HitPay** (SGD) — `PaymentID` is the payment request ID. Register your webhook URL in the dashboard (Developers > Webhook Endpoints) and subscribe to `payment_request.completed`. `ValidateWebhook` checks the JSON body against your salt and rejects events that aren't `payment_request`. For sandbox, use `WithBaseURL("https://api.sandbox.hit-pay.com")`.
- **toyyibPay** (MYR) — `PaymentID` is the bill code. Bills are FPX-only, fixed-amount and at least MYR 1.00. `Description` becomes the bill name (trimmed to 30 characters) and description (trimmed to 100); characters other than letters, digits, spaces and `_` are removed. The callback hash doesn't cover `billcode`, so confirm with `Payment` before fulfilling. For sandbox, use `WithBaseURL("https://dev.toyyibpay.com")`.
- **PayMongo** (PHP) — `PaymentID` is the Checkout Session ID (`cs_...`). `PaymentMethodTypes` is required (e.g. `qrph`, `gcash`, `paymaya`, `card`). Register your webhook in the dashboard (Settings > Webhooks) and subscribe to `checkout_session.payment.paid`. `ValidateWebhook` rejects events for other resources with `ErrInvalidWebhook`; respond 200 to those so PayMongo doesn't retry. There's no separate sandbox URL: use an `sk_test_` key.

### Amounts and currency

`Amount` is an `int64` in the currency's minor unit as defined by ISO 4217, and
`Currency` is the ISO 4217 code. For example `1050` + `"MYR"` is MYR 10.50, and
`1000000` + `"IDR"` is IDR 10,000. Adapters reject currencies they don't
support with `ErrUnsupportedCurrency`.

### Errors

Adapters wrap these sentinel errors, so check them with `errors.Is`:

| Error                    | Meaning                                              |
|--------------------------|------------------------------------------------------|
| `ErrInvalidSignature`    | Webhook signature is missing or doesn't match        |
| `ErrInvalidWebhook`      | Webhook request is malformed or missing fields       |
| `ErrUnsupportedCurrency` | Provider doesn't support the requested currency      |
| `ErrNotFound`            | Provider reports the payment doesn't exist           |

## Adding a provider

Implement `gadapters.Provider` in a new sub-package:

```go
type Provider interface {
	ID(ctx context.Context) string       // e.g. "billplz", matches the package name
	Name(ctx context.Context) string     // display name, e.g. "Billplz"
	Country(ctx context.Context) Country // ISO 3166-1 alpha-3, e.g. "MYS"
	GenerateCheckoutURL(ctx context.Context, req *CheckoutRequest) (*CheckoutResponse, error)
	Payment(ctx context.Context, id string) (*Payment, error)
	ValidateWebhook(ctx context.Context, r *http.Request) (string, error)
}
```

If your provider's country isn't in `country.go` yet, add a constant for it.
Add a compile-time check (`var _ gadapters.Provider = (*Client)(nil)`) and tests using `httptest.Server`.
Reject unsupported currencies with `ErrUnsupportedCurrency`, and wrap the other sentinel errors where they apply.

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

package gadapters

import (
	"context"
	"net/http"
)

type CheckoutRequest struct {
	// ReferenceID is the payment request reference ID.
	// Not to confuse with payment ID which refers to
	// the actual unique payment ID stored.
	ReferenceID string
	// Name is the name of the payer.
	Name string
	// Email is the email of the payer.
	Email string
	// Description is the description of the payment.
	Description string
	// Amount is the amount to be paid in the currency's minor unit as defined
	// by ISO 4217 (e.g. 1050 = MYR 10.50, 1000000 = IDR 10,000.00).
	Amount int64
	// Currency is the ISO 4217 currency code (e.g. "MYR", "IDR").
	Currency string
}

type CheckoutResponse struct {
	// PaymentID is the payment request PaymentID returned by the
	// provider
	PaymentID string
	// PaymentURL is the checkout PaymentURL to proceed with
	// the payment steps.
	PaymentURL string
}

// Payment is a payment record fetched from a provider.
type Payment struct {
	// PaymentID is the provider's payment/bill ID.
	PaymentID string
	// Paid reports whether the payment has been settled.
	Paid bool
	// State is the provider's raw status string (e.g. "due", "paid").
	State string
	// Amount is the amount in the currency's minor unit as defined by ISO 4217.
	Amount int64
	// Currency is the ISO 4217 currency code.
	Currency string
	// PaymentURL is the checkout/receipt URL.
	PaymentURL string
}

type Provider interface {
	// Name returns the gateway's name (e.g. "billplz").
	Name(ctx context.Context) string

	// Country returns the ISO 3166-1 alpha-3 code of the country the gateway
	// operates in.
	Country(ctx context.Context) Country

	// GenerateCheckoutURL generates the checkout URL for the payment request.
	GenerateCheckoutURL(ctx context.Context, req *CheckoutRequest) (*CheckoutResponse, error)

	// Payment fetches [Payment] by it's ID
	Payment(ctx context.Context, ID string) (*Payment, error)

	// ValidateWebhook validates the incoming webhook request against the
	// configured secret and returns the payment ID. It may consume r.Body.
	ValidateWebhook(ctx context.Context, r *http.Request) (string, error)
}

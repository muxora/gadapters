package gadapters

import "context"

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
	// Amount is the amount to be paid.
	Amount float64
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
	// Amount is the amount in the major currency unit (e.g. MYR).
	Amount float64
	// PaymentURL is the checkout/receipt URL.
	PaymentURL string
}

type Provider interface {
	// GenerateCheckoutURL generates the checkout URL for the payment request.
	GenerateCheckoutURL(ctx context.Context, req *CheckoutRequest) (*CheckoutResponse, error)

	// Payment fetches [Payment] by it's ID
	Payment(ctx context.Context, ID string) (*Payment, error)

	// ValidateWebhook validates webhook payload against configured secret and return the
	// payment ID
	ValidateWebhook(ctx context.Context, payload []byte) (string, error)
}

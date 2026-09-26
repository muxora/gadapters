package gadapters

import "errors"

var (
	// ErrInvalidSignature is returned when a webhook signature is missing or
	// does not match.
	ErrInvalidSignature = errors.New("invalid webhook signature")
	// ErrInvalidWebhook is returned when a webhook request is malformed or
	// missing required fields.
	ErrInvalidWebhook = errors.New("invalid webhook")
	// ErrUnsupportedCurrency is returned when a provider does not support the
	// requested currency.
	ErrUnsupportedCurrency = errors.New("unsupported currency")
	// ErrNotFound is returned when the provider reports that a payment does
	// not exist.
	ErrNotFound = errors.New("payment not found")
)

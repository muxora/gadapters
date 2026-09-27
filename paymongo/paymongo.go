package paymongo

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/muxora/gadapters"
)

var _ gadapters.Provider = (*Client)(nil)

const currency = "PHP"

type Config struct {
	// SecretKey is the API secret key (sk_test_... or sk_live_...). The key
	// prefix selects test or live mode; the base URL is the same.
	SecretKey string
	// WebhookSecret is the signing secret of the webhook endpoint registered
	// in the dashboard (whsk_...).
	WebhookSecret string
	// PaymentMethodTypes lists the methods offered on the checkout page, e.g.
	// "qrph", "gcash", "paymaya", "card". Required by PayMongo.
	PaymentMethodTypes []string
	// SuccessURL is where the payer is sent after a successful payment.
	// Optional.
	SuccessURL string
	// CancelURL is where the payer is sent when they leave the checkout.
	// Optional.
	CancelURL string
}

type Option func(*Client)

func WithBaseURL(baseURL string) Option {
	return func(c *Client) { c.baseURL = baseURL }
}

func WithSlogLogger(logger *slog.Logger) Option {
	return func(c *Client) { c.logger = logger }
}

func WithHttpClient(httpClient *http.Client) Option {
	return func(c *Client) { c.httpClient = httpClient }
}

func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = timeout }
}

type Client struct {
	httpClient *http.Client

	baseURL string
	logger  *slog.Logger
	conf    Config
}

func New(conf Config, opts ...Option) *Client {
	c := &Client{
		baseURL:    "https://api.paymongo.com",
		httpClient: &http.Client{Timeout: 5 * time.Second},
		logger:     slog.Default(),
		conf:       conf,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

func (c *Client) ID(ctx context.Context) string {
	return "paymongo"
}

func (c *Client) Name(ctx context.Context) string {
	return "PayMongo"
}

func (c *Client) Country(ctx context.Context) gadapters.Country {
	return gadapters.CountryPhilippines
}

type lineItem struct {
	Name     string `json:"name"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Quantity int64  `json:"quantity"`
}

// GenerateCheckoutURL creates a PayMongo Checkout Session with a single line
// item and returns its checkout URL.
// See https://docs.paymongo.com/reference/create_checkout_sessions_2.
func (c *Client) GenerateCheckoutURL(
	ctx context.Context,
	req *gadapters.CheckoutRequest,
) (*gadapters.CheckoutResponse, error) {
	if req.Currency != currency {
		return nil, fmt.Errorf("paymongo: %w: %q", gadapters.ErrUnsupportedCurrency, req.Currency)
	}
	if len(c.conf.PaymentMethodTypes) == 0 {
		return nil, fmt.Errorf("paymongo: payment method types are required")
	}

	name := req.Description
	if name == "" {
		name = "Payment"
	}

	type billing struct {
		Name  string `json:"name,omitempty"`
		Email string `json:"email,omitempty"`
	}
	type attributes struct {
		Billing            *billing   `json:"billing,omitempty"`
		Description        string     `json:"description,omitempty"`
		LineItems          []lineItem `json:"line_items"`
		PaymentMethodTypes []string   `json:"payment_method_types"`
		ReferenceNumber    string     `json:"reference_number,omitempty"`
		SuccessURL         string     `json:"success_url,omitempty"`
		CancelURL          string     `json:"cancel_url,omitempty"`
	}
	attrs := attributes{
		Description:        req.Description,
		LineItems:          []lineItem{{Name: name, Amount: req.Amount, Currency: currency, Quantity: 1}},
		PaymentMethodTypes: c.conf.PaymentMethodTypes,
		ReferenceNumber:    req.ReferenceID,
		SuccessURL:         c.conf.SuccessURL,
		CancelURL:          c.conf.CancelURL,
	}
	if req.Name != "" || req.Email != "" {
		attrs.Billing = &billing{Name: req.Name, Email: req.Email}
	}

	body, err := json.Marshal(map[string]any{"data": map[string]any{"attributes": attrs}})
	if err != nil {
		return nil, fmt.Errorf("paymongo: unable to marshal payload: %w", err)
	}

	data, err := c.do(ctx, http.MethodPost, "/v2/checkout_sessions", body)
	if err != nil {
		return nil, err
	}

	var out struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				CheckoutURL string `json:"checkout_url"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("paymongo: unable to unmarshal response: %w", err)
	}

	return &gadapters.CheckoutResponse{PaymentID: out.Data.ID, PaymentURL: out.Data.Attributes.CheckoutURL}, nil
}

// Payment fetches a Checkout Session by its ID. Paid is true once any of its
// payments is paid or its payment intent has succeeded.
// See https://docs.paymongo.com/reference/get_checkout_sessions.
func (c *Client) Payment(ctx context.Context, id string) (*gadapters.Payment, error) {
	data, err := c.do(ctx, http.MethodGet, "/v1/checkout_sessions/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}

	var out struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				CheckoutURL string     `json:"checkout_url"`
				Status      string     `json:"status"`
				LineItems   []lineItem `json:"line_items"`
				Payments    []struct {
					Attributes struct {
						Status string `json:"status"`
					} `json:"attributes"`
				} `json:"payments"`
				PaymentIntent *struct {
					Attributes struct {
						Status string `json:"status"`
					} `json:"attributes"`
				} `json:"payment_intent"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("paymongo: unable to unmarshal response: %w", err)
	}
	attrs := out.Data.Attributes

	var amount int64
	for _, li := range attrs.LineItems {
		amount += li.Amount * li.Quantity
	}

	state := attrs.Status
	paid := false
	if attrs.PaymentIntent != nil && attrs.PaymentIntent.Attributes.Status != "" {
		state = attrs.PaymentIntent.Attributes.Status
		paid = state == "succeeded"
	}
	for _, p := range attrs.Payments {
		if p.Attributes.Status == "paid" {
			paid = true
		}
	}

	return &gadapters.Payment{
		PaymentID:  out.Data.ID,
		Paid:       paid,
		State:      state,
		Amount:     amount,
		Currency:   currency,
		PaymentURL: attrs.CheckoutURL,
	}, nil
}

// ValidateWebhook verifies the Paymongo-Signature header
// (t=<timestamp>,te=<test sig>,li=<live sig>): HMAC-SHA256 of
// "<timestamp>.<raw body>" keyed with the webhook secret. It returns the
// Checkout Session ID. Events for other resources are rejected with
// [gadapters.ErrInvalidWebhook].
// See https://docs.paymongo.com/docs/developer-tools-webhook-setup-management.
func (c *Client) ValidateWebhook(ctx context.Context, r *http.Request) (string, error) {
	header := r.Header.Get("Paymongo-Signature")
	if header == "" {
		return "", fmt.Errorf("paymongo: %w: missing Paymongo-Signature", gadapters.ErrInvalidSignature)
	}

	var timestamp, testSig, liveSig string
	for part := range strings.SplitSeq(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			timestamp = v
		case "te":
			testSig = v
		case "li":
			liveSig = v
		}
	}
	got := liveSig
	if got == "" {
		got = testSig
	}
	if timestamp == "" || got == "" {
		return "", fmt.Errorf("paymongo: %w: malformed Paymongo-Signature", gadapters.ErrInvalidSignature)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("paymongo: %w: %w", gadapters.ErrInvalidWebhook, err)
	}

	mac := hmac.New(sha256.New, []byte(c.conf.WebhookSecret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(got), []byte(want)) {
		return "", fmt.Errorf("paymongo: %w", gadapters.ErrInvalidSignature)
	}

	var event struct {
		Data struct {
			Attributes struct {
				Type string `json:"type"`
				Data struct {
					ID   string `json:"id"`
					Type string `json:"type"`
				} `json:"data"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &event); err != nil {
		return "", fmt.Errorf("paymongo: %w: %w", gadapters.ErrInvalidWebhook, err)
	}
	resource := event.Data.Attributes.Data
	if resource.Type != "checkout_session" {
		return "", fmt.Errorf(
			"paymongo: %w: unexpected event %q", gadapters.ErrInvalidWebhook, event.Data.Attributes.Type,
		)
	}
	if resource.ID == "" {
		return "", fmt.Errorf("paymongo: %w: missing checkout session id", gadapters.ErrInvalidWebhook)
	}
	return resource.ID, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("paymongo: unable to create request: %w", err)
	}
	// HTTP Basic auth: secret key as username, empty password.
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.conf.SecretKey+":")))
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("paymongo: unable to send request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("paymongo: unable to read response: %w", err)
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("paymongo: %w: %s", gadapters.ErrNotFound, path)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("paymongo: status is not OK: %v", string(data))
	}
	return data, nil
}

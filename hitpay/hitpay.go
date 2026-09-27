package hitpay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/muxora/gadapters"
)

var _ gadapters.Provider = (*Client)(nil)

const currency = "SGD"

type Config struct {
	APIKey string
	// Salt is the webhook salt from the HitPay dashboard, used to verify the
	// Hitpay-Signature header.
	Salt string
	// RedirectURL is where the payer is sent after payment. Optional.
	RedirectURL string
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
		baseURL:    "https://api.hit-pay.com",
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
	return "hitpay"
}

func (c *Client) Name(ctx context.Context) string {
	return "HitPay"
}

func (c *Client) Country(ctx context.Context) gadapters.Country {
	return gadapters.CountrySingapore
}

// GenerateCheckoutURL creates a HitPay payment request and returns its
// checkout URL. See https://docs.hitpayapp.com/apis/payment-request/create-request.
func (c *Client) GenerateCheckoutURL(
	ctx context.Context,
	req *gadapters.CheckoutRequest,
) (*gadapters.CheckoutResponse, error) {
	if req.Currency != currency {
		return nil, fmt.Errorf("hitpay: %w: %q", gadapters.ErrUnsupportedCurrency, req.Currency)
	}

	vals := url.Values{}
	vals.Set("amount", formatAmount(req.Amount))
	vals.Set("currency", currency)
	vals.Set("email", req.Email)
	vals.Set("name", req.Name)
	vals.Set("purpose", req.Description)
	vals.Set("reference_number", req.ReferenceID)
	if c.conf.RedirectURL != "" {
		vals.Set("redirect_url", c.conf.RedirectURL)
	}

	data, err := c.do(ctx, http.MethodPost, "/v1/payment-requests", strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}

	var out struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("hitpay: unable to unmarshal response: %w", err)
	}

	return &gadapters.CheckoutResponse{PaymentID: out.ID, PaymentURL: out.URL}, nil
}

// Payment fetches a payment request by its ID.
// See https://docs.hitpayapp.com/apis/payment-request/get-payment-status.
func (c *Client) Payment(ctx context.Context, id string) (*gadapters.Payment, error) {
	data, err := c.do(ctx, http.MethodGet, "/v1/payment-requests/"+url.PathEscape(id), nil)
	if err != nil {
		return nil, err
	}

	var out struct {
		ID       string `json:"id"`
		Status   string `json:"status"`
		Amount   string `json:"amount"`
		Currency string `json:"currency"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("hitpay: unable to unmarshal response: %w", err)
	}

	amount, err := parseAmount(out.Amount)
	if err != nil {
		return nil, fmt.Errorf("hitpay: invalid amount %q: %w", out.Amount, err)
	}

	return &gadapters.Payment{
		PaymentID:  out.ID,
		Paid:       out.Status == "completed",
		State:      out.Status,
		Amount:     amount,
		Currency:   strings.ToUpper(out.Currency),
		PaymentURL: out.URL,
	}, nil
}

// ValidateWebhook verifies the Hitpay-Signature of a dashboard-registered
// webhook: HMAC-SHA256 of the raw JSON body keyed with the salt.
// See https://docs.hitpayapp.com/apis/guide/online-payments#validating-the-webhook.
// Only payment_request events are accepted.
func (c *Client) ValidateWebhook(ctx context.Context, r *http.Request) (string, error) {
	got := r.Header.Get("Hitpay-Signature")
	if got == "" {
		return "", fmt.Errorf("hitpay: %w: missing Hitpay-Signature", gadapters.ErrInvalidSignature)
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("hitpay: %w: %w", gadapters.ErrInvalidWebhook, err)
	}

	mac := hmac.New(sha256.New, []byte(c.conf.Salt))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(got), []byte(want)) {
		return "", fmt.Errorf("hitpay: %w", gadapters.ErrInvalidSignature)
	}

	if obj := r.Header.Get("Hitpay-Event-Object"); obj != "" && obj != "payment_request" {
		return "", fmt.Errorf("hitpay: %w: unexpected event object %q", gadapters.ErrInvalidWebhook, obj)
	}

	var payload struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("hitpay: %w: %w", gadapters.ErrInvalidWebhook, err)
	}
	if payload.ID == "" {
		return "", fmt.Errorf("hitpay: %w: missing id", gadapters.ErrInvalidWebhook)
	}
	return payload.ID, nil
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("hitpay: unable to create request: %w", err)
	}
	httpReq.Header.Set("X-BUSINESS-API-KEY", c.conf.APIKey)
	httpReq.Header.Set("X-Requested-With", "XMLHttpRequest")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("hitpay: unable to send request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("hitpay: unable to read response: %w", err)
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("hitpay: %w: %s", gadapters.ErrNotFound, path)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("hitpay: status is not OK: %v", string(data))
	}
	return data, nil
}

// formatAmount converts minor units (cents) to HitPay's decimal string.
func formatAmount(cents int64) string {
	return fmt.Sprintf("%d.%02d", cents/100, cents%100)
}

// parseAmount converts HitPay's decimal string (e.g. "10.50") to cents
// without going through floating point.
func parseAmount(s string) (int64, error) {
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > 2 {
		return 0, fmt.Errorf("too many decimal places")
	}
	frac += strings.Repeat("0", 2-len(frac))

	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, err
	}
	return w*100 + int64(f), nil
}

package senangpay

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/muxora/gadapters"
)

var _ gadapters.Provider = (*Client)(nil)

const currency = "MYR"

type Config struct {
	MerchantID string
	SecretKey  string
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
		baseURL:    "https://app.senangpay.my",
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
	return "senangpay"
}

func (c *Client) Name(ctx context.Context) string {
	return "senangPay"
}

func (c *Client) Country(ctx context.Context) gadapters.Country {
	return gadapters.CountryMalaysia
}

// GenerateCheckoutURL builds the senangPay redirect URL for the payment request.
// The hash is HMAC-SHA256(secretKey, detail+amount+order_id) keyed by secretKey.
func (c *Client) GenerateCheckoutURL(
	ctx context.Context,
	req *gadapters.CheckoutRequest,
) (*gadapters.CheckoutResponse, error) {
	if req.Currency != currency {
		return nil, fmt.Errorf("senangpay: %w: %q", gadapters.ErrUnsupportedCurrency, req.Currency)
	}

	u, err := url.Parse(c.baseURL + "/payment/" + c.conf.MerchantID)
	if err != nil {
		return nil, fmt.Errorf("senangpay: unable to parse url: %w", err)
	}

	amount := fmt.Sprintf("%d.%02d", req.Amount/100, req.Amount%100)
	toHash := c.conf.SecretKey + req.Description + amount + req.ReferenceID
	mac := hmac.New(sha256.New, []byte(c.conf.SecretKey))
	mac.Write([]byte(toHash))

	q := u.Query()
	q.Set("detail", req.Description)
	q.Set("amount", amount)
	q.Set("order_id", req.ReferenceID)
	q.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	q.Set("name", req.Name)
	q.Set("email", req.Email)
	u.RawQuery = q.Encode()

	return &gadapters.CheckoutResponse{PaymentID: req.ReferenceID, PaymentURL: u.String()}, nil
}

// Payment queries an order's status by its order_id (the checkout ReferenceID).
// See https://api-guide.senangpay.my/ (Query Order Status). The hash for this
// endpoint is md5(merchant_id + secret_key + order_id).
func (c *Client) Payment(ctx context.Context, id string) (*gadapters.Payment, error) {
	sum := md5.Sum([]byte(c.conf.MerchantID + c.conf.SecretKey + id))

	u, err := url.Parse(c.baseURL + "/apiv1/query_order_status")
	if err != nil {
		return nil, fmt.Errorf("senangpay: unable to parse url: %w", err)
	}
	q := u.Query()
	q.Set("merchant_id", c.conf.MerchantID)
	q.Set("order_id", id)
	q.Set("hash", hex.EncodeToString(sum[:]))
	u.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("senangpay: unable to create request: %w", err)
	}

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("senangpay: unable to send request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("senangpay: unable to read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("senangpay: status is not OK: %v", string(data))
	}

	var out struct {
		Status     int         `json:"status"`
		AmountPaid json.Number `json:"amount_paid"`
		Msg        string      `json:"msg"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("senangpay: unable to unmarshal response: %w", err)
	}

	amount, _ := out.AmountPaid.Int64() // amount_paid is in cents
	return &gadapters.Payment{
		PaymentID: id,
		Paid:      out.Status == 1, // 1 = success
		State:     out.Msg,
		Amount:    amount,
		Currency:  currency,
	}, nil
}

// ValidateWebhook verifies the hash of a senangPay callback (POST form) or
// return (GET query) request. Both carry the same params. The hash is
// HMAC-SHA256(secretKey, secretKey+status_id+order_id+transaction_id+msg).
// It returns the order_id, matching the PaymentID from GenerateCheckoutURL.
func (c *Client) ValidateWebhook(ctx context.Context, r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("senangpay: %w: %w", gadapters.ErrInvalidWebhook, err)
	}
	values := r.Form

	got := values.Get("hash")
	if got == "" {
		return "", fmt.Errorf("senangpay: %w: missing hash", gadapters.ErrInvalidSignature)
	}

	source := c.conf.SecretKey + values.Get(
		"status_id",
	) + values.Get(
		"order_id",
	) + values.Get(
		"transaction_id",
	) + values.Get(
		"msg",
	)
	mac := hmac.New(sha256.New, []byte(c.conf.SecretKey))
	mac.Write([]byte(source))
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(got), []byte(want)) {
		return "", fmt.Errorf("senangpay: %w", gadapters.ErrInvalidSignature)
	}
	return values.Get("order_id"), nil
}

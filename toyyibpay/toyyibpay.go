package toyyibpay

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
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

const currency = "MYR"

// minAmount is toyyibPay's minimum bill amount (MYR 1.00).
const minAmount = 100

type Config struct {
	UserSecretKey string
	// CategoryCode is the category bills are created under. Create one in the
	// toyyibPay dashboard or via the Create Category API.
	CategoryCode string
	// CallbackURL is where toyyibPay POSTs the payment result. Optional, but
	// required to receive webhooks.
	CallbackURL string
	// ReturnURL is where the payer is sent after payment. Optional.
	ReturnURL string
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
		baseURL:    "https://toyyibpay.com",
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
	return "toyyibpay"
}

func (c *Client) Name(ctx context.Context) string {
	return "toyyibPay"
}

func (c *Client) Country(ctx context.Context) gadapters.Country {
	return gadapters.CountryMalaysia
}

// GenerateCheckoutURL creates a fixed-amount toyyibPay bill and returns its
// payment URL. See https://toyyibpay.com/apireference/#cb.
//
// Description is used as the bill name and description; characters toyyibPay
// rejects are stripped and it is truncated to fit.
func (c *Client) GenerateCheckoutURL(
	ctx context.Context,
	req *gadapters.CheckoutRequest,
) (*gadapters.CheckoutResponse, error) {
	if req.Currency != currency {
		return nil, fmt.Errorf("toyyibpay: %w: %q", gadapters.ErrUnsupportedCurrency, req.Currency)
	}
	if req.Amount < minAmount {
		return nil, fmt.Errorf("toyyibpay: amount %d is below the minimum of %d", req.Amount, minAmount)
	}

	vals := url.Values{}
	vals.Set("userSecretKey", c.conf.UserSecretKey)
	vals.Set("categoryCode", c.conf.CategoryCode)
	vals.Set("billName", sanitize(req.Description, 30))
	vals.Set("billDescription", sanitize(req.Description, 100))
	vals.Set("billPriceSetting", "1")
	vals.Set("billPayorInfo", "1")
	vals.Set("billAmount", strconv.FormatInt(req.Amount, 10))
	vals.Set("billReturnUrl", c.conf.ReturnURL)
	vals.Set("billCallbackUrl", c.conf.CallbackURL)
	vals.Set("billExternalReferenceNo", req.ReferenceID)
	vals.Set("billTo", req.Name)
	vals.Set("billEmail", req.Email)
	vals.Set("billPaymentChannel", "0") // FPX

	data, err := c.post(ctx, "/index.php/api/createBill", vals)
	if err != nil {
		return nil, err
	}

	// Failures also come back as HTTP 200, as a JSON object or plain text.
	var out []struct {
		BillCode string `json:"BillCode"`
	}
	if err := json.Unmarshal(data, &out); err != nil || len(out) == 0 || out[0].BillCode == "" {
		return nil, fmt.Errorf("toyyibpay: unable to create bill: %s", strings.TrimSpace(string(data)))
	}

	code := out[0].BillCode
	return &gadapters.CheckoutResponse{PaymentID: code, PaymentURL: c.billURL(code)}, nil
}

// Payment fetches a bill's transactions by bill code and reports the
// successful one if any, otherwise the latest attempt. A bill with no
// transactions yet is returned as unpaid with an empty State.
// See https://toyyibpay.com/apireference/#gbt.
func (c *Client) Payment(ctx context.Context, id string) (*gadapters.Payment, error) {
	data, err := c.post(ctx, "/index.php/api/getBillTransactions", url.Values{"billCode": {id}})
	if err != nil {
		return nil, err
	}

	var txs []struct {
		Status string `json:"billpaymentStatus"`
		Amount string `json:"billpaymentAmount"`
	}
	if err := json.Unmarshal(data, &txs); err != nil {
		return nil, fmt.Errorf("toyyibpay: unable to unmarshal response: %s", strings.TrimSpace(string(data)))
	}

	p := &gadapters.Payment{PaymentID: id, Currency: currency, PaymentURL: c.billURL(id)}
	if len(txs) == 0 {
		return p, nil
	}

	tx := txs[len(txs)-1]
	for _, t := range txs {
		if t.Status == "1" {
			tx = t
			break
		}
	}

	amount, err := parseAmount(tx.Amount)
	if err != nil {
		return nil, fmt.Errorf("toyyibpay: invalid amount %q: %w", tx.Amount, err)
	}

	p.Paid = tx.Status == "1"
	p.State = statusName(tx.Status)
	p.Amount = amount
	return p, nil
}

// ValidateWebhook verifies the hash of a toyyibPay callback (POST form):
// MD5(userSecretKey + status + order_id + refno + "ok"). It returns the
// billcode.
//
// The hash does not cover billcode, so confirm the result with [Client.Payment]
// before fulfilling.
// See https://toyyibpay.com/apireference/#cp.
func (c *Client) ValidateWebhook(ctx context.Context, r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("toyyibpay: %w: %w", gadapters.ErrInvalidWebhook, err)
	}
	values := r.PostForm

	got := values.Get("hash")
	if got == "" {
		return "", fmt.Errorf("toyyibpay: %w: missing hash", gadapters.ErrInvalidSignature)
	}

	sum := md5.Sum([]byte(
		c.conf.UserSecretKey + values.Get("status") + values.Get("order_id") + values.Get("refno") + "ok",
	))
	want := hex.EncodeToString(sum[:])

	if !hmac.Equal([]byte(got), []byte(want)) {
		return "", fmt.Errorf("toyyibpay: %w", gadapters.ErrInvalidSignature)
	}

	code := values.Get("billcode")
	if code == "" {
		return "", fmt.Errorf("toyyibpay: %w: missing billcode", gadapters.ErrInvalidWebhook)
	}
	return code, nil
}

func (c *Client) billURL(code string) string {
	return c.baseURL + "/" + url.PathEscape(code)
}

func (c *Client) post(ctx context.Context, path string, vals url.Values) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+path,
		strings.NewReader(vals.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("toyyibpay: unable to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("toyyibpay: unable to send request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("toyyibpay: unable to read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("toyyibpay: status is not OK: %v", string(data))
	}
	return data, nil
}

func statusName(status string) string {
	switch status {
	case "1":
		return "success"
	case "2", "4":
		return "pending"
	case "3":
		return "failed"
	default:
		return status
	}
}

// sanitize keeps only the characters toyyibPay allows in bill names and
// descriptions (alphanumerics, space and '_') and truncates to max.
func sanitize(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r == ' ' || r == '_' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > max {
		out = strings.TrimSpace(out[:max])
	}
	if out == "" {
		return "Payment"
	}
	return out
}

// parseAmount converts toyyibPay's decimal string (e.g. "10.50") to sen
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

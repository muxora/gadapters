package billplz

import (
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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/muxora/gadapters"
)

var _ gadapters.Provider = (*Client)(nil)

const currency = "MYR"

type Config struct {
	CollectionID string
	SecretKey    string
	// CallbackURL is the webhook Billplz POSTs to after payment. Required by
	// the Create a Bill API.
	CallbackURL string
	// RedirectURL is where the payer is sent after payment. Optional; when
	// empty Billplz shows its own receipt page.
	RedirectURL   string
	XSignatureKey string
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
		baseURL:    "https://www.billplz.com/api",
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
	return "billplz"
}

func (c *Client) Name(ctx context.Context) string {
	return "Billplz"
}

func (c *Client) Country(ctx context.Context) gadapters.Country {
	return gadapters.CountryMalaysia
}

// GenerateCheckoutURL creates a Billplz Bill and returns its payment URL.
// See https://support.billplz.com/api#v3-bills-create-a-bill.
func (c *Client) GenerateCheckoutURL(
	ctx context.Context,
	req *gadapters.CheckoutRequest,
) (*gadapters.CheckoutResponse, error) {
	if c.conf.CallbackURL == "" {
		return nil, fmt.Errorf("billplz: callback URL is required")
	}
	if req.Currency != currency {
		return nil, fmt.Errorf("billplz: %w: %q", gadapters.ErrUnsupportedCurrency, req.Currency)
	}

	vals := url.Values{}
	vals.Set("collection_id", c.conf.CollectionID)
	vals.Set("description", req.Description)
	vals.Set("email", req.Email)
	vals.Set("name", req.Name)
	// Billplz expects the amount in cents (MYR only).
	vals.Set("amount", strconv.FormatInt(req.Amount, 10))
	vals.Set("callback_url", c.conf.CallbackURL)
	vals.Set("reference_1_label", "payment_id")
	vals.Set("reference_1", req.ReferenceID)
	if c.conf.RedirectURL != "" {
		vals.Set("redirect_url", c.conf.RedirectURL)
	}

	endpoint := c.baseURL + "/v3/bills"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, fmt.Errorf("billplz: unable to create request: %w", err)
	}
	// HTTP Basic auth: secret key as username, empty password (trailing colon).
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.conf.SecretKey+":")))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("billplz: unable to send request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("billplz: unable to read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("billplz: status is not OK: %v", string(data))
	}

	var out struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("billplz: unable to unmarshal response: %w", err)
	}

	return &gadapters.CheckoutResponse{PaymentID: out.ID, PaymentURL: out.URL}, nil
}

// Payment fetches a Bill by its ID.
// See https://support.billplz.com/api#v3-bills-get-a-bill.
func (c *Client) Payment(ctx context.Context, id string) (*gadapters.Payment, error) {
	endpoint := c.baseURL + "/v3/bills/" + url.PathEscape(id)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("billplz: unable to create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.conf.SecretKey+":")))

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("billplz: unable to send request: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("billplz: unable to read response: %w", err)
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("billplz: %w: %s", gadapters.ErrNotFound, id)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("billplz: status is not OK: %v", string(data))
	}

	var out struct {
		ID     string `json:"id"`
		Paid   bool   `json:"paid"`
		State  string `json:"state"`
		Amount int64  `json:"amount"` // cents
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("billplz: unable to unmarshal response: %w", err)
	}

	return &gadapters.Payment{
		PaymentID:  out.ID,
		Paid:       out.Paid,
		State:      out.State,
		Amount:     out.Amount,
		Currency:   currency,
		PaymentURL: out.URL,
	}, nil
}

// ValidateWebhook verifies the X Signature of a Billplz callback request.
// See https://support.billplz.com/api#x-signature. The request is the
// form-urlencoded POST Billplz sends to the callback URL.
func (c *Client) ValidateWebhook(ctx context.Context, r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("billplz: %w: %w", gadapters.ErrInvalidWebhook, err)
	}
	values := r.PostForm

	got := values.Get("x_signature")
	if got == "" {
		return "", fmt.Errorf("billplz: %w: missing x_signature", gadapters.ErrInvalidSignature)
	}

	parts := make([]string, 0, len(values))
	for k := range values {
		if k != "x_signature" {
			parts = append(parts, k+values.Get(k))
		}
	}
	sort.Strings(parts)

	mac := hmac.New(sha256.New, []byte(c.conf.XSignatureKey))
	mac.Write([]byte(strings.Join(parts, "|")))
	want := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(got), []byte(want)) {
		return "", fmt.Errorf("billplz: %w", gadapters.ErrInvalidSignature)
	}
	return values.Get("id"), nil
}

package ipaymu

import (
	"bytes"
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
	"time"

	"github.com/muxora/gadapters"
)

var _ gadapters.Provider = (*Client)(nil)

type Config struct {
	VA     string
	APIKey string
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
		baseURL:    "https://my.ipaymu.com/api/v2",
		httpClient: &http.Client{Timeout: 5 * time.Second},
		logger:     slog.Default(),
		conf:       conf,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GenerateCheckoutURL creates an iPaymu redirect payment and returns its URL.
// The returned PaymentID is the iPaymu SessionId; the numeric transactionId
// used by Payment only exists after the payer completes (sent to the notify URL).
func (c *Client) GenerateCheckoutURL(ctx context.Context, req *gadapters.CheckoutRequest) (*gadapters.CheckoutResponse, error) {
	payload := map[string]any{
		"product":     []string{req.Description},
		"qty":         []string{"1"},
		"price":       []string{strconv.Itoa(int(req.Amount))},
		"description": []string{req.Description},
		"referenceId": req.ReferenceID,
		"lang":        "en",
	}

	data, err := c.post(ctx, "/payment", payload)
	if err != nil {
		return nil, err
	}

	var out struct {
		Data struct {
			SessionID string `json:"SessionID"`
			URL       string `json:"Url"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("ipaymu: unable to unmarshal response: %w", err)
	}

	return &gadapters.CheckoutResponse{PaymentID: out.Data.SessionID, PaymentURL: out.Data.URL}, nil
}

// Payment fetches a transaction by its iPaymu transactionId.
// See https://docs.ipaymu.com/en/docs/transaction/check-transaction.
func (c *Client) Payment(ctx context.Context, id string) (*gadapters.Payment, error) {
	data, err := c.post(ctx, "/transaction", map[string]any{"transactionId": id})
	if err != nil {
		return nil, err
	}

	var out struct {
		Data struct {
			TransactionID int64       `json:"TransactionId"`
			Amount        json.Number `json:"Amount"`
			Status        int         `json:"Status"`
			StatusDesc    string      `json:"StatusDesc"`
		} `json:"Data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("ipaymu: unable to unmarshal response: %w", err)
	}

	amount, _ := out.Data.Amount.Float64()
	return &gadapters.Payment{
		PaymentID: strconv.FormatInt(out.Data.TransactionID, 10),
		Paid:      out.Data.Status == 1, // 1 = Success
		State:     out.Data.StatusDesc,
		Amount:    amount,
	}, nil
}

// post marshals payload to JSON, signs it, POSTs to baseURL+path, and returns
// the raw response body. Signature: HMAC-SHA256(POST:VA:sha256(body):APIKey).
func (c *Client) post(ctx context.Context, path string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("ipaymu: unable to marshal payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ipaymu: unable to create request: %w", err)
	}

	bodyHash := sha256.Sum256(body)
	stringToSign := fmt.Sprintf("%s:%s:%s:%s", http.MethodPost, c.conf.VA, hex.EncodeToString(bodyHash[:]), c.conf.APIKey)
	mac := hmac.New(sha256.New, []byte(c.conf.APIKey))
	mac.Write([]byte(stringToSign))

	httpReq.Header.Set("signature", hex.EncodeToString(mac.Sum(nil)))
	httpReq.Header.Set("timestamp", time.Now().Format("20060102150405"))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("va", c.conf.VA)

	res, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ipaymu: unable to send request: %w", err)
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("ipaymu: unable to read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipaymu: status is not OK: %v", string(data))
	}
	return data, nil
}

// ValidateWebhook verifies an iPaymu notification. iPaymu notifications are
// unsigned, so authenticity is confirmed server-to-server by re-querying the
// transaction with the configured VA/API key.
func (c *Client) ValidateWebhook(ctx context.Context, payload []byte) (string, error) {
	values, err := url.ParseQuery(string(payload))
	if err != nil {
		return "", fmt.Errorf("ipaymu: unable to parse webhook payload: %w", err)
	}

	trxID := values.Get("trx_id")
	if trxID == "" {
		return "", fmt.Errorf("ipaymu: missing trx_id")
	}

	if _, err := c.Payment(ctx, trxID); err != nil {
		return "", fmt.Errorf("ipaymu: webhook verification failed: %w", err)
	}
	return trxID, nil
}

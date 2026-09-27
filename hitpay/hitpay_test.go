package hitpay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/muxora/gadapters"
)

func TestGenerateCheckoutURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/v1/payment-requests" {
			t.Errorf("path = %q, want /v1/payment-requests", r.URL.Path)
		}
		if got := r.Header.Get("X-BUSINESS-API-KEY"); got != "key" {
			t.Errorf("X-BUSINESS-API-KEY = %q, want key", got)
		}
		if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
			t.Errorf("X-Requested-With = %q, want XMLHttpRequest", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		want := map[string]string{
			"amount":           "10.05",
			"currency":         "SGD",
			"email":            "ali@example.com",
			"name":             "Ali",
			"purpose":          "Order",
			"reference_number": "ref-1",
			"redirect_url":     "https://example.com/thanks",
		}
		for k, v := range want {
			if got := r.PostFormValue(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"pr-123","url":"https://securecheckout.hit-pay.com/pr-123/checkout"}`))
	}))
	defer srv.Close()

	c := New(Config{APIKey: "key", RedirectURL: "https://example.com/thanks"}, WithBaseURL(srv.URL))

	res, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Name:        "Ali",
		Email:       "ali@example.com",
		Description: "Order",
		Amount:      1005,
		Currency:    "SGD",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PaymentID != "pr-123" {
		t.Errorf("PaymentID = %q, want pr-123", res.PaymentID)
	}
	if res.PaymentURL != "https://securecheckout.hit-pay.com/pr-123/checkout" {
		t.Errorf("PaymentURL = %q", res.PaymentURL)
	}
}

func TestGenerateCheckoutURLNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"bad"}`))
	}))
	defer srv.Close()

	c := New(Config{APIKey: "key"}, WithBaseURL(srv.URL))

	if _, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 100, Currency: "SGD"},
	); err == nil {
		t.Fatal("expected error on non-OK status, got nil")
	}
}

func TestGenerateCheckoutURLUnsupportedCurrency(t *testing.T) {
	c := New(Config{APIKey: "key"})

	_, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 100, Currency: "MYR"},
	)
	if !errors.Is(err, gadapters.ErrUnsupportedCurrency) {
		t.Fatalf("err = %v, want ErrUnsupportedCurrency", err)
	}
}

func TestPayment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/v1/payment-requests/pr-123" {
			t.Errorf("path = %q, want /v1/payment-requests/pr-123", r.URL.Path)
		}
		if got := r.Header.Get("X-BUSINESS-API-KEY"); got != "key" {
			t.Errorf("X-BUSINESS-API-KEY = %q, want key", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			`{"id":"pr-123","status":"completed","amount":"10.50","currency":"sgd","url":"https://pay.example/pr-123"}`,
		))
	}))
	defer srv.Close()

	c := New(Config{APIKey: "key"}, WithBaseURL(srv.URL))

	p, err := c.Payment(context.Background(), "pr-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PaymentID != "pr-123" || !p.Paid || p.State != "completed" {
		t.Errorf("got id=%q paid=%v state=%q, want pr-123/true/completed", p.PaymentID, p.Paid, p.State)
	}
	if p.Amount != 1050 || p.Currency != "SGD" {
		t.Errorf("got amount=%d currency=%q, want 1050/SGD", p.Amount, p.Currency)
	}
	if p.PaymentURL != "https://pay.example/pr-123" {
		t.Errorf("PaymentURL = %q", p.PaymentURL)
	}
}

func TestPaymentNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"No query results"}`))
	}))
	defer srv.Close()

	c := New(Config{APIKey: "key"}, WithBaseURL(srv.URL))

	if _, err := c.Payment(context.Background(), "missing"); !errors.Is(err, gadapters.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func sign(body, salt string) string {
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func webhookRequest(body, signature, object string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if signature != "" {
		r.Header.Set("Hitpay-Signature", signature)
	}
	if object != "" {
		r.Header.Set("Hitpay-Event-Object", object)
	}
	return r
}

func TestValidateWebhook(t *testing.T) {
	c := New(Config{Salt: "salt"})
	body := `{"id":"pr-123","status":"completed","amount":"10.50","currency":"SGD"}`

	id, err := c.ValidateWebhook(context.Background(), webhookRequest(body, sign(body, "salt"), "payment_request"))
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if id != "pr-123" {
		t.Errorf("payment id = %q, want pr-123", id)
	}

	tampered := strings.Replace(body, "10.50", "99.99", 1)
	_, err = c.ValidateWebhook(context.Background(), webhookRequest(tampered, sign(body, "salt"), "payment_request"))
	if !errors.Is(err, gadapters.ErrInvalidSignature) {
		t.Fatalf("tampered payload: err = %v, want ErrInvalidSignature", err)
	}

	_, err = c.ValidateWebhook(context.Background(), webhookRequest(body, "", "payment_request"))
	if !errors.Is(err, gadapters.ErrInvalidSignature) {
		t.Fatalf("missing signature: err = %v, want ErrInvalidSignature", err)
	}

	_, err = c.ValidateWebhook(context.Background(), webhookRequest(body, sign(body, "salt"), "charge"))
	if !errors.Is(err, gadapters.ErrInvalidWebhook) {
		t.Fatalf("non payment_request event: err = %v, want ErrInvalidWebhook", err)
	}
}

func TestAmount(t *testing.T) {
	for cents, s := range map[int64]string{0: "0.00", 5: "0.05", 1050: "10.50", 99999: "999.99"} {
		if got := formatAmount(cents); got != s {
			t.Errorf("formatAmount(%d) = %q, want %q", cents, got, s)
		}
	}
	for s, cents := range map[string]int64{"10.50": 1050, "10.5": 1050, "10": 1000, "0.05": 5} {
		got, err := parseAmount(s)
		if err != nil || got != cents {
			t.Errorf("parseAmount(%q) = %d, %v, want %d", s, got, err, cents)
		}
	}
	for _, s := range []string{"", "abc", "1.234", "1.-5"} {
		if _, err := parseAmount(s); err == nil {
			t.Errorf("parseAmount(%q) expected error", s)
		}
	}
}

func TestMetadata(t *testing.T) {
	c := New(Config{})

	if got := c.ID(context.Background()); got != "hitpay" {
		t.Errorf("ID = %q, want hitpay", got)
	}
	if got := c.Name(context.Background()); got != "HitPay" {
		t.Errorf("Name = %q, want HitPay", got)
	}
	if got := c.Country(context.Background()); got != "SGP" {
		t.Errorf("Country = %q, want SGP", got)
	}
}

package billplz

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/muxora/gadapters"
)

func wantAuth(secretKey string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(secretKey+":"))
}

func TestGenerateCheckoutURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/bills" {
			t.Errorf("path = %q, want /v3/bills", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth("sk") {
			t.Errorf("Authorization = %q, want %q", got, wantAuth("sk"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.PostFormValue("amount"); got != "1050" {
			t.Errorf("amount = %q, want 1050", got)
		}
		if got := r.PostFormValue("collection_id"); got != "col" {
			t.Errorf("collection_id = %q, want col", got)
		}
		if got := r.PostFormValue("callback_url"); got != "https://cb.example/hook" {
			t.Errorf("callback_url = %q, want https://cb.example/hook", got)
		}
		if got := r.PostFormValue("reference_1"); got != "ref-1" {
			t.Errorf("reference_1 = %q, want ref-1", got)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"bill-123","url":"https://pay.example/bill-123"}`))
	}))
	defer srv.Close()

	c := New(Config{CollectionID: "col", SecretKey: "sk", CallbackURL: "https://cb.example/hook"}, WithBaseURL(srv.URL))

	res, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Name:        "Ali",
		Email:       "ali@example.com",
		Description: "Order",
		Amount:      10.50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PaymentID != "bill-123" {
		t.Errorf("PaymentID = %q, want bill-123", res.PaymentID)
	}
	if res.PaymentURL != "https://pay.example/bill-123" {
		t.Errorf("PaymentURL = %q, want https://pay.example/bill-123", res.PaymentURL)
	}
}

func TestGenerateCheckoutURLRequiresCallback(t *testing.T) {
	c := New(Config{CollectionID: "col", SecretKey: "sk"})

	if _, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{ReferenceID: "x"}); err == nil {
		t.Fatal("expected error when callback URL is missing, got nil")
	}
}

func TestGenerateCheckoutURLNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":"bad"}`))
	}))
	defer srv.Close()

	c := New(Config{CollectionID: "col", SecretKey: "sk", CallbackURL: "https://cb.example/hook"}, WithBaseURL(srv.URL))

	if _, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{ReferenceID: "x"}); err == nil {
		t.Fatal("expected error on non-OK status, got nil")
	}
}

func TestPayment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/v3/bills/bill-123" {
			t.Errorf("path = %q, want /v3/bills/bill-123", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth("sk") {
			t.Errorf("Authorization = %q, want %q", got, wantAuth("sk"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"bill-123","paid":true,"state":"paid","amount":1050,"url":"https://pay.example/bill-123"}`))
	}))
	defer srv.Close()

	c := New(Config{SecretKey: "sk"}, WithBaseURL(srv.URL))

	p, err := c.Payment(context.Background(), "bill-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.Paid || p.State != "paid" {
		t.Errorf("got paid=%v state=%q, want true/paid", p.Paid, p.State)
	}
	if p.Amount != 10.50 {
		t.Errorf("Amount = %v, want 10.50", p.Amount)
	}
}

func TestValidateWebhook(t *testing.T) {
	c := New(Config{SecretKey: "sk", XSignatureKey: "xsig"})

	fields := map[string]string{
		"id":          "bill-123",
		"paid":        "true",
		"state":       "paid",
		"amount":      "1050",
		"paid_amount": "1050",
	}
	form := url.Values{}
	for k, v := range fields {
		form.Set(k, v)
	}

	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		parts = append(parts, k+v)
	}
	sort.Strings(parts)
	mac := hmac.New(sha256.New, []byte("xsig"))
	mac.Write([]byte(strings.Join(parts, "|")))
	form.Set("x_signature", hex.EncodeToString(mac.Sum(nil)))

	id, err := c.ValidateWebhook(context.Background(), []byte(form.Encode()))
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if id != "bill-123" {
		t.Errorf("payment id = %q, want bill-123", id)
	}

	form.Set("amount", "9999")
	if _, err := c.ValidateWebhook(context.Background(), []byte(form.Encode())); err == nil {
		t.Fatal("expected error on tampered payload, got nil")
	}
}

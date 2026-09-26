package senangpay

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/muxora/gadapters"
)

func TestGenerateCheckoutURL(t *testing.T) {
	c := New(Config{MerchantID: "merch-1", SecretKey: "secret"})

	req := &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Name:        "Ali",
		Email:       "ali@example.com",
		Description: "Order",
		Amount:      1050,
		Currency:    "MYR",
	}

	res, err := c.GenerateCheckoutURL(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PaymentID != "ref-1" {
		t.Errorf("ID = %q, want ref-1", res.PaymentID)
	}

	u, err := url.Parse(res.PaymentURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if u.Path != "/payment/merch-1" {
		t.Errorf("path = %q, want /payment/merch-1", u.Path)
	}

	q := u.Query()
	if q.Get("amount") != "10.50" {
		t.Errorf("amount = %q, want 10.50", q.Get("amount"))
	}
	if q.Get("order_id") != "ref-1" {
		t.Errorf("order_id = %q, want ref-1", q.Get("order_id"))
	}

	toHash := "secret" + "Order" + "10.50" + "ref-1"
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(toHash))
	if want := hex.EncodeToString(mac.Sum(nil)); q.Get("hash") != want {
		t.Errorf("hash = %q, want %q", q.Get("hash"), want)
	}
}

func TestGenerateCheckoutURLUnsupportedCurrency(t *testing.T) {
	c := New(Config{MerchantID: "merch-1", SecretKey: "secret"})

	_, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 100, Currency: "IDR"},
	)
	if !errors.Is(err, gadapters.ErrUnsupportedCurrency) {
		t.Fatalf("err = %v, want ErrUnsupportedCurrency", err)
	}
}

func TestPayment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apiv1/query_order_status" {
			t.Errorf("path = %q, want /apiv1/query_order_status", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("merchant_id") != "merch-1" {
			t.Errorf("merchant_id = %q, want merch-1", q.Get("merchant_id"))
		}
		if q.Get("order_id") != "ref-1" {
			t.Errorf("order_id = %q, want ref-1", q.Get("order_id"))
		}
		sum := md5.Sum([]byte("merch-1" + "secret" + "ref-1"))
		if want := hex.EncodeToString(sum[:]); q.Get("hash") != want {
			t.Errorf("hash = %q, want %q", q.Get("hash"), want)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(
			[]byte(
				`{"status":1,"transaction_id":"tx-99","order_id":"ref-1","amount_paid":1050,"msg":"Payment was successful"}`,
			),
		)
	}))
	defer srv.Close()

	c := New(Config{MerchantID: "merch-1", SecretKey: "secret"}, WithBaseURL(srv.URL))

	p, err := c.Payment(context.Background(), "ref-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PaymentID != "ref-1" {
		t.Errorf("PaymentID = %q, want ref-1", p.PaymentID)
	}
	if !p.Paid || p.State != "Payment was successful" {
		t.Errorf("got paid=%v state=%q, want true/'Payment was successful'", p.Paid, p.State)
	}
	if p.Amount != 1050 || p.Currency != "MYR" {
		t.Errorf("got amount=%d currency=%q, want 1050/MYR", p.Amount, p.Currency)
	}
}

func TestValidateWebhook(t *testing.T) {
	c := New(Config{MerchantID: "merch-1", SecretKey: "secret"})

	form := url.Values{}
	form.Set("status_id", "1")
	form.Set("order_id", "ref-1")
	form.Set("transaction_id", "tx-99")
	form.Set("msg", "Payment was successful")

	source := "secret" + "1" + "ref-1" + "tx-99" + "Payment was successful"
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte(source))
	form.Set("hash", hex.EncodeToString(mac.Sum(nil)))

	post := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	id, err := c.ValidateWebhook(context.Background(), post)
	if err != nil {
		t.Fatalf("valid callback rejected: %v", err)
	}
	if id != "ref-1" {
		t.Errorf("payment id = %q, want ref-1", id)
	}

	get := httptest.NewRequest(http.MethodGet, "/return?"+form.Encode(), nil)
	if _, err := c.ValidateWebhook(context.Background(), get); err != nil {
		t.Fatalf("valid return request rejected: %v", err)
	}

	form.Set("msg", "tampered")
	tampered := httptest.NewRequest(http.MethodGet, "/return?"+form.Encode(), nil)
	if _, err := c.ValidateWebhook(context.Background(), tampered); !errors.Is(err, gadapters.ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestPaymentIDConsistent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("order_id"); got != "ref-1" {
			t.Errorf("order_id = %q, want ref-1", got)
		}
		_, _ = w.Write([]byte(`{"status":1,"transaction_id":"tx-99","amount_paid":1050,"msg":"ok"}`))
	}))
	defer srv.Close()

	c := New(Config{MerchantID: "merch-1", SecretKey: "secret"}, WithBaseURL(srv.URL))

	checkout, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Description: "Order",
		Amount:      1050,
		Currency:    "MYR",
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}

	form := url.Values{}
	form.Set("status_id", "1")
	form.Set("order_id", "ref-1")
	form.Set("transaction_id", "tx-99")
	form.Set("msg", "ok")
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("secret" + "1" + "ref-1" + "tx-99" + "ok"))
	form.Set("hash", hex.EncodeToString(mac.Sum(nil)))

	webhookID, err := c.ValidateWebhook(
		context.Background(),
		httptest.NewRequest(http.MethodGet, "/return?"+form.Encode(), nil),
	)
	if err != nil {
		t.Fatalf("webhook: %v", err)
	}
	if webhookID != checkout.PaymentID {
		t.Fatalf("webhook id = %q, checkout id = %q, want equal", webhookID, checkout.PaymentID)
	}

	p, err := c.Payment(context.Background(), webhookID)
	if err != nil {
		t.Fatalf("payment: %v", err)
	}
	if p.PaymentID != checkout.PaymentID {
		t.Errorf("payment id = %q, checkout id = %q, want equal", p.PaymentID, checkout.PaymentID)
	}
}

func TestMetadata(t *testing.T) {
	c := New(Config{})

	if got := c.Name(context.Background()); got != "senangpay" {
		t.Errorf("Name = %q, want senangpay", got)
	}
	if got := c.Country(context.Background()); got != "MYS" {
		t.Errorf("Country = %q, want MYS", got)
	}
}

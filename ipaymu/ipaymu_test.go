package ipaymu

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/muxora/gadapters"
)

func TestGenerateCheckoutURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/payment" {
			t.Errorf("path = %q, want /payment", r.URL.Path)
		}
		if got := r.Header.Get("va"); got != "va-1" {
			t.Errorf("va = %q, want va-1", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		bodyHash := sha256.Sum256(body)
		toSign := "POST:va-1:" + hex.EncodeToString(bodyHash[:]) + ":key-1"
		mac := hmac.New(sha256.New, []byte("key-1"))
		mac.Write([]byte(toSign))
		if got, want := r.Header.Get("signature"), hex.EncodeToString(mac.Sum(nil)); got != want {
			t.Errorf("signature = %q, want %q", got, want)
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if payload["referenceId"] != "ref-1" {
			t.Errorf("referenceId = %v, want ref-1", payload["referenceId"])
		}
		if price, _ := payload["price"].([]any); len(price) != 1 || price[0] != "25000" {
			t.Errorf("price = %v, want [25000]", payload["price"])
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(
			[]byte(`{"Status":200,"Data":{"SessionID":"sess-9","Url":"https://pay.ipaymu/sess-9"},"Message":"ok"}`),
		)
	}))
	defer srv.Close()

	c := New(Config{VA: "va-1", APIKey: "key-1"}, WithBaseURL(srv.URL))

	res, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Description: "Order",
		Amount:      2500000,
		Currency:    "IDR",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PaymentID != "sess-9" {
		t.Errorf("ID = %q, want sess-9", res.PaymentID)
	}
	if res.PaymentURL != "https://pay.ipaymu/sess-9" {
		t.Errorf("URL = %q, want https://pay.ipaymu/sess-9", res.PaymentURL)
	}
}

func TestGenerateCheckoutURLNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"Message":"bad"}`))
	}))
	defer srv.Close()

	c := New(Config{VA: "va-1", APIKey: "key-1"}, WithBaseURL(srv.URL))

	if _, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Currency: "IDR"},
	); err == nil {
		t.Fatal("expected error on non-OK status, got nil")
	}
}

func TestGenerateCheckoutURLInvalidAmount(t *testing.T) {
	c := New(Config{VA: "va-1", APIKey: "key-1"})

	_, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 100, Currency: "MYR"},
	)
	if !errors.Is(err, gadapters.ErrUnsupportedCurrency) {
		t.Fatalf("err = %v, want ErrUnsupportedCurrency", err)
	}

	if _, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 150, Currency: "IDR"},
	); err == nil {
		t.Fatal("expected error for fractional rupiah, got nil")
	}
}

// verifySignature recomputes iPaymu's HMAC signature over the received body.
func verifySignature(t *testing.T, r *http.Request, va, apiKey string) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyHash := sha256.Sum256(body)
	toSign := "POST:" + va + ":" + hex.EncodeToString(bodyHash[:]) + ":" + apiKey
	mac := hmac.New(sha256.New, []byte(apiKey))
	mac.Write([]byte(toSign))
	if got, want := r.Header.Get("signature"), hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("signature = %q, want %q", got, want)
	}
	return body
}

func TestPayment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transaction" {
			t.Errorf("path = %q, want /transaction", r.URL.Path)
		}
		body := verifySignature(t, r, "va-1", "key-1")
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if payload["transactionId"] != "4719" {
			t.Errorf("transactionId = %v, want 4719", payload["transactionId"])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(
			[]byte(
				`{"Status":200,"Success":true,"Data":{"TransactionId":4719,"Amount":10000,"Status":1,"StatusDesc":"Berhasil","PaidStatus":"paid"}}`,
			),
		)
	}))
	defer srv.Close()

	c := New(Config{VA: "va-1", APIKey: "key-1"}, WithBaseURL(srv.URL))

	p, err := c.Payment(context.Background(), "4719")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PaymentID != "4719" {
		t.Errorf("PaymentID = %q, want 4719", p.PaymentID)
	}
	if !p.Paid || p.State != "Berhasil" {
		t.Errorf("got paid=%v state=%q, want true/Berhasil", p.Paid, p.State)
	}
	if p.Amount != 1000000 || p.Currency != "IDR" {
		t.Errorf("got amount=%d currency=%q, want 1000000/IDR", p.Amount, p.Currency)
	}
}

func TestValidateWebhook(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/transaction" {
			t.Errorf("path = %q, want /transaction", r.URL.Path)
		}
		body := verifySignature(t, r, "va-1", "key-1")
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if payload["transactionId"] != "4719" {
			t.Errorf("transactionId = %v, want 4719", payload["transactionId"])
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Status":200,"Data":{"TransactionId":4719,"Status":1,"StatusDesc":"Berhasil"}}`))
	}))
	defer srv.Close()

	c := New(Config{VA: "va-1", APIKey: "key-1"}, WithBaseURL(srv.URL))

	notify := url.Values{"trx_id": {"4719"}, "status": {"berhasil"}}
	req := httptest.NewRequest(http.MethodPost, "/notify", strings.NewReader(notify.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	id, err := c.ValidateWebhook(context.Background(), req)
	if err != nil {
		t.Fatalf("valid webhook rejected: %v", err)
	}
	if id != "4719" {
		t.Errorf("payment id = %q, want 4719", id)
	}
	if hits != 1 {
		t.Errorf("re-query hits = %d, want 1", hits)
	}

	missing := httptest.NewRequest(http.MethodPost, "/notify", strings.NewReader("status=berhasil"))
	missing.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := c.ValidateWebhook(context.Background(), missing); !errors.Is(err, gadapters.ErrInvalidWebhook) {
		t.Fatalf("err = %v, want ErrInvalidWebhook", err)
	}
}

func TestMetadata(t *testing.T) {
	c := New(Config{})

	if got := c.Name(context.Background()); got != "ipaymu" {
		t.Errorf("Name = %q, want ipaymu", got)
	}
	if got := c.Country(context.Background()); got != "IDN" {
		t.Errorf("Country = %q, want IDN", got)
	}
}

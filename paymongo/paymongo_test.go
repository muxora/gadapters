package paymongo

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/muxora/gadapters"
)

func wantAuth(secretKey string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(secretKey+":"))
}

func TestGenerateCheckoutURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/v2/checkout_sessions" {
			t.Errorf("path = %q, want /v2/checkout_sessions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth("sk_test") {
			t.Errorf("Authorization = %q, want %q", got, wantAuth("sk_test"))
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var in struct {
			Data struct {
				Attributes struct {
					Billing struct {
						Name  string `json:"name"`
						Email string `json:"email"`
					} `json:"billing"`
					Description        string     `json:"description"`
					LineItems          []lineItem `json:"line_items"`
					PaymentMethodTypes []string   `json:"payment_method_types"`
					ReferenceNumber    string     `json:"reference_number"`
					SuccessURL         string     `json:"success_url"`
					CancelURL          string     `json:"cancel_url"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		a := in.Data.Attributes
		if a.Billing.Name != "Juan" || a.Billing.Email != "juan@example.com" {
			t.Errorf("billing = %+v, want Juan/juan@example.com", a.Billing)
		}
		if a.Description != "Order #1" || a.ReferenceNumber != "ref-1" {
			t.Errorf("description=%q reference_number=%q", a.Description, a.ReferenceNumber)
		}
		want := lineItem{Name: "Order #1", Amount: 10050, Currency: "PHP", Quantity: 1}
		if len(a.LineItems) != 1 || a.LineItems[0] != want {
			t.Errorf("line_items = %+v, want [%+v]", a.LineItems, want)
		}
		if strings.Join(a.PaymentMethodTypes, ",") != "qrph,gcash" {
			t.Errorf("payment_method_types = %v, want [qrph gcash]", a.PaymentMethodTypes)
		}
		if a.SuccessURL != "https://example.com/ok" || a.CancelURL != "https://example.com/cart" {
			t.Errorf("success_url=%q cancel_url=%q", a.SuccessURL, a.CancelURL)
		}

		_, _ = w.Write([]byte(
			`{"data":{"id":"cs_123","type":"checkout_session",` +
				`"attributes":{"checkout_url":"https://checkout.paymongo.com/cs_123"}}}`,
		))
	}))
	defer srv.Close()

	c := New(Config{
		SecretKey:          "sk_test",
		PaymentMethodTypes: []string{"qrph", "gcash"},
		SuccessURL:         "https://example.com/ok",
		CancelURL:          "https://example.com/cart",
	}, WithBaseURL(srv.URL))

	res, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Name:        "Juan",
		Email:       "juan@example.com",
		Description: "Order #1",
		Amount:      10050,
		Currency:    "PHP",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PaymentID != "cs_123" {
		t.Errorf("PaymentID = %q, want cs_123", res.PaymentID)
	}
	if res.PaymentURL != "https://checkout.paymongo.com/cs_123" {
		t.Errorf("PaymentURL = %q", res.PaymentURL)
	}
}

func TestGenerateCheckoutURLNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":[{"code":"parameter_required","detail":"bad"}]}`))
	}))
	defer srv.Close()

	c := New(Config{SecretKey: "sk_test", PaymentMethodTypes: []string{"qrph"}}, WithBaseURL(srv.URL))

	if _, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 10000, Currency: "PHP"},
	); err == nil {
		t.Fatal("expected error on non-OK status, got nil")
	}
}

func TestGenerateCheckoutURLValidation(t *testing.T) {
	c := New(Config{SecretKey: "sk_test", PaymentMethodTypes: []string{"qrph"}})

	_, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 10000, Currency: "MYR"},
	)
	if !errors.Is(err, gadapters.ErrUnsupportedCurrency) {
		t.Fatalf("err = %v, want ErrUnsupportedCurrency", err)
	}

	c = New(Config{SecretKey: "sk_test"})
	if _, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 10000, Currency: "PHP"},
	); err == nil {
		t.Fatal("expected error when payment method types are missing, got nil")
	}
}

func TestPayment(t *testing.T) {
	tests := []struct {
		name      string
		attrs     string
		wantPaid  bool
		wantState string
	}{
		{
			name: "paid",
			attrs: `"status":"active",` +
				`"payments":[{"attributes":{"status":"paid"}}],` +
				`"payment_intent":{"attributes":{"status":"succeeded"}}`,
			wantPaid:  true,
			wantState: "succeeded",
		},
		{
			name:      "awaiting payment",
			attrs:     `"status":"active","payments":[],"payment_intent":{"attributes":{"status":"awaiting_payment_method"}}`,
			wantPaid:  false,
			wantState: "awaiting_payment_method",
		},
		{
			name:      "no payment intent",
			attrs:     `"status":"expired","payments":[],"payment_intent":null`,
			wantPaid:  false,
			wantState: "expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("method = %q, want GET", r.Method)
				}
				if r.URL.Path != "/v1/checkout_sessions/cs_123" {
					t.Errorf("path = %q, want /v1/checkout_sessions/cs_123", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != wantAuth("sk_test") {
					t.Errorf("Authorization = %q, want %q", got, wantAuth("sk_test"))
				}
				_, _ = w.Write([]byte(`{"data":{"id":"cs_123","type":"checkout_session","attributes":{` +
					`"checkout_url":"https://checkout.paymongo.com/cs_123",` +
					`"line_items":[{"name":"a","amount":550,"currency":"PHP","quantity":2},` +
					`{"name":"b","amount":1000,"currency":"PHP","quantity":1}],` +
					tt.attrs + `}}}`))
			}))
			defer srv.Close()

			c := New(Config{SecretKey: "sk_test"}, WithBaseURL(srv.URL))

			p, err := c.Payment(context.Background(), "cs_123")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.PaymentID != "cs_123" || p.Paid != tt.wantPaid || p.State != tt.wantState {
				t.Errorf("got id=%q paid=%v state=%q, want cs_123/%v/%q",
					p.PaymentID, p.Paid, p.State, tt.wantPaid, tt.wantState)
			}
			if p.Amount != 2100 || p.Currency != "PHP" {
				t.Errorf("got amount=%d currency=%q, want 2100/PHP", p.Amount, p.Currency)
			}
			if p.PaymentURL != "https://checkout.paymongo.com/cs_123" {
				t.Errorf("PaymentURL = %q", p.PaymentURL)
			}
		})
	}
}

func TestPaymentNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"resource_not_found"}]}`))
	}))
	defer srv.Close()

	c := New(Config{SecretKey: "sk_test"}, WithBaseURL(srv.URL))

	if _, err := c.Payment(context.Background(), "missing"); !errors.Is(err, gadapters.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func sign(timestamp, body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "." + body))
	return hex.EncodeToString(mac.Sum(nil))
}

func webhookRequest(body, signature string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if signature != "" {
		r.Header.Set("Paymongo-Signature", signature)
	}
	return r
}

func event(eventType, resourceType, id string) string {
	return `{"data":{"id":"evt_1","type":"event","attributes":{"type":"` + eventType +
		`","livemode":false,"data":{"id":"` + id + `","type":"` + resourceType + `","attributes":{}}}}}`
}

func TestValidateWebhook(t *testing.T) {
	c := New(Config{WebhookSecret: "whsk"})
	body := event("checkout_session.payment.paid", "checkout_session", "cs_123")

	for name, header := range map[string]string{
		"test mode": "t=1700000000,te=" + sign("1700000000", body, "whsk") + ",li=",
		"live mode": "t=1700000000,te=,li=" + sign("1700000000", body, "whsk"),
	} {
		id, err := c.ValidateWebhook(context.Background(), webhookRequest(body, header))
		if err != nil {
			t.Fatalf("%s: valid signature rejected: %v", name, err)
		}
		if id != "cs_123" {
			t.Errorf("%s: payment id = %q, want cs_123", name, id)
		}
	}

	tampered := strings.Replace(body, "cs_123", "cs_999", 1)
	header := "t=1700000000,te=" + sign("1700000000", body, "whsk") + ",li="
	if _, err := c.ValidateWebhook(context.Background(), webhookRequest(tampered, header)); !errors.Is(
		err,
		gadapters.ErrInvalidSignature,
	) {
		t.Fatalf("tampered payload: err = %v, want ErrInvalidSignature", err)
	}

	otherTS := "t=1700000001,te=" + sign("1700000000", body, "whsk") + ",li="
	if _, err := c.ValidateWebhook(context.Background(), webhookRequest(body, otherTS)); !errors.Is(
		err,
		gadapters.ErrInvalidSignature,
	) {
		t.Fatalf("changed timestamp: err = %v, want ErrInvalidSignature", err)
	}

	for _, h := range []string{"", "garbage", "t=1700000000,te=,li="} {
		if _, err := c.ValidateWebhook(context.Background(), webhookRequest(body, h)); !errors.Is(
			err,
			gadapters.ErrInvalidSignature,
		) {
			t.Fatalf("header %q: err = %v, want ErrInvalidSignature", h, err)
		}
	}

	payment := event("payment.paid", "payment", "pay_123")
	header = "t=1700000000,te=" + sign("1700000000", payment, "whsk") + ",li="
	if _, err := c.ValidateWebhook(context.Background(), webhookRequest(payment, header)); !errors.Is(
		err,
		gadapters.ErrInvalidWebhook,
	) {
		t.Fatalf("non checkout_session event: err = %v, want ErrInvalidWebhook", err)
	}
}

func TestMetadata(t *testing.T) {
	c := New(Config{})

	if got := c.ID(context.Background()); got != "paymongo" {
		t.Errorf("ID = %q, want paymongo", got)
	}
	if got := c.Name(context.Background()); got != "PayMongo" {
		t.Errorf("Name = %q, want PayMongo", got)
	}
	if got := c.Country(context.Background()); got != "PHL" {
		t.Errorf("Country = %q, want PHL", got)
	}
}

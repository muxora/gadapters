package toyyibpay

import (
	"context"
	"crypto/md5"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/index.php/api/createBill" {
			t.Errorf("path = %q, want /index.php/api/createBill", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		want := map[string]string{
			"userSecretKey":           "sk",
			"categoryCode":            "cat",
			"billName":                "Order 123",
			"billDescription":         "Order 123",
			"billPriceSetting":        "1",
			"billPayorInfo":           "1",
			"billAmount":              "1050",
			"billReturnUrl":           "https://example.com/thanks",
			"billCallbackUrl":         "https://example.com/hook",
			"billExternalReferenceNo": "ref-1",
			"billTo":                  "Ali",
			"billEmail":               "ali@example.com",
		}
		for k, v := range want {
			if got := r.PostFormValue(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		_, _ = w.Write([]byte(`[{"BillCode":"gcbhict9"}]`))
	}))
	defer srv.Close()

	c := New(Config{
		UserSecretKey: "sk",
		CategoryCode:  "cat",
		CallbackURL:   "https://example.com/hook",
		ReturnURL:     "https://example.com/thanks",
	}, WithBaseURL(srv.URL))

	res, err := c.GenerateCheckoutURL(context.Background(), &gadapters.CheckoutRequest{
		ReferenceID: "ref-1",
		Name:        "Ali",
		Email:       "ali@example.com",
		Description: "Order #123",
		Amount:      1050,
		Currency:    "MYR",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PaymentID != "gcbhict9" {
		t.Errorf("PaymentID = %q, want gcbhict9", res.PaymentID)
	}
	if res.PaymentURL != srv.URL+"/gcbhict9" {
		t.Errorf("PaymentURL = %q, want %s/gcbhict9", res.PaymentURL, srv.URL)
	}
}

func TestGenerateCheckoutURLFailureBody(t *testing.T) {
	for _, body := range []string{
		`{"status":"error","msg":"billName exceed limit. Max 30 length"}`,
		`[KEY-DID-NOT-EXIST]`,
		`[]`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))

		c := New(Config{UserSecretKey: "sk", CategoryCode: "cat"}, WithBaseURL(srv.URL))
		_, err := c.GenerateCheckoutURL(
			context.Background(),
			&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 100, Currency: "MYR"},
		)
		if err == nil {
			t.Errorf("body %q: expected error, got nil", body)
		}
		srv.Close()
	}
}

func TestGenerateCheckoutURLValidation(t *testing.T) {
	c := New(Config{UserSecretKey: "sk", CategoryCode: "cat"})

	_, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 1000, Currency: "SGD"},
	)
	if !errors.Is(err, gadapters.ErrUnsupportedCurrency) {
		t.Fatalf("err = %v, want ErrUnsupportedCurrency", err)
	}

	if _, err := c.GenerateCheckoutURL(
		context.Background(),
		&gadapters.CheckoutRequest{ReferenceID: "x", Amount: 99, Currency: "MYR"},
	); err == nil {
		t.Fatal("expected error for amount below minimum, got nil")
	}
}

func TestPayment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.php/api/getBillTransactions" {
			t.Errorf("path = %q, want /index.php/api/getBillTransactions", r.URL.Path)
		}
		if got := r.PostFormValue("billCode"); got != "gcbhict9" {
			t.Errorf("billCode = %q, want gcbhict9", got)
		}
		_, _ = w.Write([]byte(`[
			{"billpaymentStatus":"3","billpaymentAmount":"10.50"},
			{"billpaymentStatus":"1","billpaymentAmount":"10.50"}
		]`))
	}))
	defer srv.Close()

	c := New(Config{}, WithBaseURL(srv.URL))

	p, err := c.Payment(context.Background(), "gcbhict9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PaymentID != "gcbhict9" || !p.Paid || p.State != "success" {
		t.Errorf("got id=%q paid=%v state=%q, want gcbhict9/true/success", p.PaymentID, p.Paid, p.State)
	}
	if p.Amount != 1050 || p.Currency != "MYR" {
		t.Errorf("got amount=%d currency=%q, want 1050/MYR", p.Amount, p.Currency)
	}
	if p.PaymentURL != srv.URL+"/gcbhict9" {
		t.Errorf("PaymentURL = %q", p.PaymentURL)
	}
}

func TestPaymentNoTransactions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := New(Config{}, WithBaseURL(srv.URL))

	p, err := c.Payment(context.Background(), "gcbhict9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Paid || p.State != "" || p.Amount != 0 {
		t.Errorf("got paid=%v state=%q amount=%d, want false/\"\"/0", p.Paid, p.State, p.Amount)
	}
}

func callbackForm(secret string) url.Values {
	form := url.Values{
		"refno":    {"TP123"},
		"status":   {"1"},
		"reason":   {"Approved"},
		"billcode": {"gcbhict9"},
		"order_id": {"ref-1"},
		"amount":   {"10.50"},
	}
	sum := md5.Sum([]byte(secret + "1" + "ref-1" + "TP123" + "ok"))
	form.Set("hash", hex.EncodeToString(sum[:]))
	return form
}

func formRequest(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestValidateWebhook(t *testing.T) {
	c := New(Config{UserSecretKey: "sk"})

	id, err := c.ValidateWebhook(context.Background(), formRequest(callbackForm("sk")))
	if err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	if id != "gcbhict9" {
		t.Errorf("payment id = %q, want gcbhict9", id)
	}

	tampered := callbackForm("sk")
	tampered.Set("status", "3")
	if _, err := c.ValidateWebhook(context.Background(), formRequest(tampered)); !errors.Is(
		err,
		gadapters.ErrInvalidSignature,
	) {
		t.Fatalf("tampered payload: err = %v, want ErrInvalidSignature", err)
	}

	missing := callbackForm("sk")
	missing.Del("hash")
	if _, err := c.ValidateWebhook(context.Background(), formRequest(missing)); !errors.Is(
		err,
		gadapters.ErrInvalidSignature,
	) {
		t.Fatalf("missing hash: err = %v, want ErrInvalidSignature", err)
	}

	noCode := callbackForm("sk")
	noCode.Del("billcode")
	if _, err := c.ValidateWebhook(context.Background(), formRequest(noCode)); !errors.Is(
		err,
		gadapters.ErrInvalidWebhook,
	) {
		t.Fatalf("missing billcode: err = %v, want ErrInvalidWebhook", err)
	}
}

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"Order #123":                            "Order 123",
		"Kuih_Raya (x2)":                        "Kuih_Raya x2",
		"!!!":                                   "Payment",
		"":                                      "Payment",
		"abcdefghijklmnopqrstuvwxyz 0123456789": "abcdefghijklmnopqrstuvwxyz 012",
	}
	for in, want := range cases {
		if got := sanitize(in, 30); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMetadata(t *testing.T) {
	c := New(Config{})

	if got := c.ID(context.Background()); got != "toyyibpay" {
		t.Errorf("ID = %q, want toyyibpay", got)
	}
	if got := c.Name(context.Background()); got != "toyyibPay" {
		t.Errorf("Name = %q, want toyyibPay", got)
	}
	if got := c.Country(context.Background()); got != "MYS" {
		t.Errorf("Country = %q, want MYS", got)
	}
}

package qwiktoday

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Pagination struct {
	Page      int   `json:"page"`
	Limit     int   `json:"limit"`
	Total     int64 `json:"total"`
	TotalPage int64 `json:"total_page"`
}
type SoundboxUser struct {
	ID                   uint      `json:"id"`
	UUID                 string    `json:"uuid"`
	IsActive             bool      `json:"is_active"`
	OutstandingBilling   float64   `json:"outstanding_billing"`
	MID                  string    `json:"mid"`
	NMID                 string    `json:"nmid"`
	DailySubscriptionFee float64   `json:"daily_subscription_fee"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}
type SoundboxUserDetail struct {
	ID                 uint                   `json:"id"`
	UUID               string                 `json:"uuid"`
	SoundboxID         uint                   `json:"soundbox_id"`
	UserID             uint                   `json:"user_id"`
	IsActive           bool                   `json:"is_active"`
	OutstandingBilling float64                `json:"outstanding_billing"`
	ApplicationAllow   []string               `json:"application_allow"`
	ApplicationAllowID []int64                `json:"application_allow_id"`
	Soundbox           map[string]interface{} `json:"soundbox"`
	TSM                map[string]interface{} `json:"tsm"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}
type Billing struct {
	ID                   uint       `json:"id"`
	UUID                 string     `json:"uuid"`
	SoundboxUserUUID     string     `json:"soundbox_user_uuid"`
	SoundboxUUID         string     `json:"soundbox_uuid"`
	SerialNumber         string     `json:"serial_number"`
	BillingDate          time.Time  `json:"billing_date"`
	DailySubscriptionFee float64    `json:"daily_subscription_fee"`
	AmountPaid           float64    `json:"amount_paid"`
	OutstandingAmount    float64    `json:"outstanding_amount"`
	IsPaid               bool       `json:"is_paid"`
	PaidAt               *time.Time `json:"paid_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}
type BillingList struct {
	Billings []Billing `json:"billings"`
	Total    float64   `json:"total"`
}
type SoundboxNotificationRequest struct {
	Amount string `json:"amount"`
}
type BillingPaymentRequest struct {
	BillingUUIDs  []string `json:"billing_uuids"`
	PaymentMethod string   `json:"payment_method,omitempty"`
}
type BillingPayment struct {
	UUID          string    `json:"uuid"`
	Amount        float64   `json:"amount"`
	Status        string    `json:"status"`
	PaymentMethod string    `json:"payment_method"`
	PaymentURL    string    `json:"payment_url"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (c *Client) Test(ctx context.Context, key, secret string) (map[string]interface{}, error) {
	var envelope struct {
		Data map[string]interface{} `json:"data"`
	}
	err := c.signedJSON(ctx, http.MethodPost, "/api/client/test", key, secret, nil, &envelope)
	return envelope.Data, err
}

func (c *Client) ListSoundboxUsers(ctx context.Context, key, secret string, page, limit int) ([]SoundboxUser, *Pagination, error) {
	query := url.Values{}
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	var envelope struct {
		Data       []SoundboxUser `json:"data"`
		Pagination Pagination     `json:"pagination"`
	}
	err := c.signedJSON(ctx, http.MethodGet, "/api/client/soundbox-user?"+query.Encode(), key, secret, nil, &envelope)
	return envelope.Data, &envelope.Pagination, err
}

func (c *Client) GetSoundboxUser(ctx context.Context, key, secret, uuid string) (*SoundboxUserDetail, error) {
	var envelope struct {
		Data SoundboxUserDetail `json:"data"`
	}
	err := c.signedJSON(ctx, http.MethodGet, "/api/client/soundbox-user/"+url.PathEscape(uuid), key, secret, nil, &envelope)
	return &envelope.Data, err
}

func (c *Client) ListBillings(ctx context.Context, key, secret, status string) (*BillingList, error) {
	query := url.Values{}
	if status != "" {
		query.Set("status", status)
	}
	var envelope struct {
		Data BillingList `json:"data"`
	}
	err := c.signedJSON(ctx, http.MethodGet, "/api/client/billings?"+query.Encode(), key, secret, nil, &envelope)
	return &envelope.Data, err
}

func (c *Client) PayBillings(ctx context.Context, key, secret string, payload BillingPaymentRequest) (*BillingPayment, error) {
	var envelope struct {
		Data BillingPayment `json:"data"`
	}
	err := c.signedJSON(ctx, http.MethodPost, "/api/client/billings/payment", key, secret, payload, &envelope)
	return &envelope.Data, err
}

func (c *Client) SendSoundboxNotification(ctx context.Context, key, secret, soundboxUserUUID string, payload SoundboxNotificationRequest) (map[string]interface{}, error) {
	var envelope struct {
		Data map[string]interface{} `json:"data"`
	}
	err := c.signedJSON(ctx, http.MethodPost, "/api/client/soundbox-user/"+url.PathEscape(soundboxUserUUID)+"/notification", key, secret, payload, &envelope)
	return envelope.Data, err
}

func (c *Client) signedJSON(ctx context.Context, method, path, key, secret string, body, target interface{}) error {
	if key == "" || secret == "" {
		return fmt.Errorf("%w: credential key and secret are required", ErrInvalidConfiguration)
	}
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	SignRequest(req, key, secret, encoded)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return decodeAPIError(resp.StatusCode, raw)
	}
	if target != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, target); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

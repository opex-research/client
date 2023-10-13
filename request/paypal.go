package request

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

type PaypalConfig struct {
	ReferenceID string
	AmountValue string
	ReturnURL   string
	CancelURL   string
}

type UnitAmount struct {
	CurrencyCode string `json:"currency_code"`
	Value        string `json:"value"`
}

type Item struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Quantity    string     `json:"quantity"`
	UnitAmount  UnitAmount `json:"unit_amount"`
}

type ItemTotal struct {
	CurrencyCode string `json:"currency_code"`
	Value        string `json:"value"`
}

type Breakdown struct {
	ItemTotal ItemTotal `json:"item_total"`
}

type Amount struct {
	CurrencyCode string    `json:"currency_code"`
	Value        string    `json:"value"`
	Breakdown    Breakdown `json:"breakdown"`
}

type PurchaseUnit struct {
	ReferenceID string `json:"reference_id,omitempty"`
	Items       []Item `json:"items,omitempty"`
	Amount      Amount `json:"amount"`
}

type ApplicationContext struct {
	ReturnURL string `json:"return_url"`
	CancelURL string `json:"cancel_url"`
}

type PaypalRequestBody struct {
	Intent             string             `json:"intent"`
	PurchaseUnits      []PurchaseUnit     `json:"purchase_units"`
	ApplicationContext ApplicationContext `json:"application_context"`
}

func NewPaypalRequest(config *PaypalConfig) *PaypalRequestBody {
	return &PaypalRequestBody{
		Intent: "CAPTURE",
		PurchaseUnits: []PurchaseUnit{
			{
				Items: []Item{
					{
						Name:        "T-Shirt",
						Description: "Green XL",
						Quantity:    "1",
						UnitAmount: UnitAmount{
							CurrencyCode: "USD",
							Value:        config.AmountValue,
						},
					},
				},
				Amount: Amount{
					CurrencyCode: "USD",
					Value:        config.AmountValue,
					Breakdown: Breakdown{
						ItemTotal: ItemTotal{
							CurrencyCode: "USD",
							Value:        config.AmountValue,
						},
					},
				},
			},
		},
		ApplicationContext: ApplicationContext{
			ReturnURL: config.ReturnURL,
			CancelURL: config.CancelURL,
		},
	}
}

func PostToPaypal(endpoint string, paypalRequestID string, bearerToken string, config *PaypalConfig) error {
	body := NewPaypalRequest(config)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PayPal-Request-Id", paypalRequestID)
	req.Header.Set("Authorization", bearerToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf("Failed to post to PayPal with status: %s", resp.Status)
		return fmt.Errorf("Failed to post to PayPal with status: %s", resp.Status)
	}

	return nil
}

package request

import (
	"bufio"
	"bytes"
	tls "client/tls-fork"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/rs/zerolog/log"
)

type PaypalConfig struct {
	ReferenceID string
	AmountValue string
	ReturnURL   string
	CancelURL   string
}

type RequestTLSPayPal struct {
	ServerDomain    string
	ServerPath      string
	ProxyURL        string
	UrlPrivateParts string
	AccessToken     string
	StorageLocation string
	PaypalConfig    *PaypalConfig // Add this for paypal specific data
}

func NewRequestPayPal(serverDomain string, serverPath string, proxyURL string, paypalConfig *PaypalConfig) RequestTLSPayPal {
	return RequestTLSPayPal{
		ServerDomain:    serverDomain,
		ServerPath:      serverPath, // "testserver.origodata.io"
		ProxyURL:        proxyURL,
		UrlPrivateParts: "",
		AccessToken:     "",
		StorageLocation: "./local_storage/",
		PaypalConfig:    paypalConfig, // Set the paypal configuration
	}
}

func (r *RequestTLSPayPal) PostToPaypal(paypalRequestID string) error {
	body := NewPaypalRequest(r.PaypalConfig)

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	// tls configs
	config := &tls.Config{
		InsecureSkipVerify:       false,
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: false,
		MinVersion:               tls.VersionTLS13,
		MaxVersion:               tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
		},
		ServerName: r.ServerDomain,
	}

	// Establish a TLS connection to the proxy
	conn, err := tls.Dial("tcp", r.ProxyURL, config)
	if err != nil {
		log.Error().Err(err).Msg("tls.Dial()")
		return err
	}
	defer conn.Close()

	// Construct the HTTP request
	endpoint := "https://" + r.ServerDomain + r.ServerPath
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PayPal-Request-Id", paypalRequestID)
	req.Header.Set("Authorization", r.AccessToken)

	// Use bufio to send the HTTP request over the TLS connection
	bufr := bufio.NewReader(conn)
	bufw := bufio.NewWriter(conn)

	err = req.Write(bufw)
	if err != nil {
		log.Error().Err(err).Msg("request.Write(bufw)")
		return err
	}

	err = bufw.Flush()
	if err != nil {
		log.Error().Err(err).Msg("bufw.Flush()")
		return err
	}

	// Read the HTTP response
	resp, err := http.ReadResponse(bufr, req)
	if err != nil {
		log.Error().Err(err).Msg("http.ReadResponse(bufr, request)")
		return err
	}
	defer resp.Body.Close()

	// Handle the HTTP response (in this example, we'll just log it)
	msg, _ := ioutil.ReadAll(resp.Body)
	log.Trace().Msg("PayPal response data:")
	log.Trace().Msg(string(msg))

	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf("Failed to post to PayPal with status: %s", resp.Status)
		return fmt.Errorf("Failed to post to PayPal with status: %s", resp.Status)
	}

	return nil
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

func RequestPaypalNoProxy(endpoint string, paypalRequestID string, bearerToken string, config *PaypalConfig) error {
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

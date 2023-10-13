package request

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
)

// REPLACE Bearer Token for testing
const paypalEndpoint = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
const bearerToken = "Bearer A21AAJ_wxwIt0-LYpJ5liuVeSr9slsX8j64hwIWxQHMsAwsJo1NX0LSo8nbSnoRKBRdKaKE6oHy_PnMtpaD9xjMVC4VJ93skA"
const proxyURL = "localhost:8082" // replace with your actual proxy URL

func TestPostToPaypal(t *testing.T) {
	const serverDomain = "api-m.sandbox.paypal.com"
	const serverPath = "/v2/checkout/orders"
	const realPaypalRequestID = "7b92603e-77ed-4896-8e78-5dea2050476a" // you may want to generate a new ID every time

	config := &PaypalConfig{
		ReferenceID: "testReferenceID",
		AmountValue: "100.00",
		ReturnURL:   "https://example.com/return",
		CancelURL:   "https://example.com/cancel",
	}

	requestTLS := NewRequestPayPal(serverDomain, serverPath, proxyURL, config)
	requestTLS.AccessToken = bearerToken

	err := requestTLS.PostToPaypal(realPaypalRequestID)
	if err != nil {
		t.Fatalf("PostToPaypal failed: %v", err)
	}
}

func TestPaypalAPIConnection(t *testing.T) {
	// Setup the PayPal request
	config := &PaypalConfig{
		ReferenceID: "testReferenceID",
		AmountValue: "100.00",
		ReturnURL:   "https://example.com/return",
		CancelURL:   "https://example.com/cancel",
	}
	requestBodyStruct := NewPaypalRequest(config)

	// Convert struct to JSON
	jsonRequestBody, err := json.Marshal(requestBodyStruct)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	// Set up the HTTP request
	req, err := http.NewRequest("POST", paypalEndpoint, bytes.NewBuffer(jsonRequestBody))
	if err != nil {
		t.Fatalf("Failed to create a new request: %v", err)
	}

	// Set headers, including the bearer token
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PayPal-Request-Id", "7b92603e-77ed-4896-8e78-5dea2050476a") // Replace with actual request id or generate one
	req.Header.Set("Authorization", bearerToken)                                // Replace with your actual bearer token

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request to PayPal API: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	t.Logf("Response body: %s", bodyBytes)

	// Check if the response status is as expected
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusCreated, resp.StatusCode)
	}
}

func TestRequestPaypalNoProxy(t *testing.T) {
	const realEndpoint = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
	const realPaypalRequestID = "7b92603e-77ed-4896-8e78-5dea2050476a" // you may want to generate a new ID every time

	config := &PaypalConfig{
		ReferenceID: "testReferenceID",
		AmountValue: "100.00",
		ReturnURL:   "https://example.com/return",
		CancelURL:   "https://example.com/cancel",
	}

	err := RequestPaypalNoProxy(realEndpoint, realPaypalRequestID, bearerToken, config)
	if err != nil {
		t.Fatalf("PostToPaypal failed: %v", err)
	}
}

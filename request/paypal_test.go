package request

import (
	"testing"
)

// REPLACE Bearer Token for testing
const paypalEndpoint = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
const bearerToken = "Bearer A21AAJV5OzglxWLq7MbcDA8PJJW-nZ5M6rvIFXAgQvyhqnvaOeAKiCZkiM66mYsQ5sG7anyjylkZ42lt9qgrf-RyCtVZDrfQQ"
const proxyURL = "localhost:8082" // replace with your actual proxy URL

// func TestPostToPaypal(t *testing.T) {
// 	const serverDomain = "api-m.sandbox.paypal.com"
// 	const serverPath = "/v2/checkout/orders"
// 	const realPaypalRequestID = "7b92603e-77ed-4896-8e78-5dea2050476a" // you may want to generate a new ID every time

// 	config := &PaypalConfig{
// 		ReferenceID: "default",
// 		AmountValue: "100.00",
// 		ReturnURL:   "https://example.com/return",
// 		CancelURL:   "https://example.com/cancel",
// 	}

// 	requestTLS := NewRequestPayPal(serverDomain, serverPath, proxyURL, config)
// 	requestTLS.AccessToken = bearerToken

// 	data, err := requestTLS.PostToPaypal(true, realPaypalRequestID)
// 	if err != nil {
// 		t.Fatalf("PostToPaypal failed: %v", err)
// 	}
// 	err = requestTLS.Store(data)
// 	if err != nil {
// 		t.Fatalf("Store data failed: %v", err)
// 	}
// }

// func TestPaypalAPIConnection(t *testing.T) {
// 	// Setup the PayPal request
// 	config := &PaypalConfig{
// 		ReferenceID: "default",
// 		AmountValue: "100.00",
// 		ReturnURL:   "https://example.com/return",
// 		CancelURL:   "https://example.com/cancel",
// 	}
// 	requestBodyStruct := NewPaypalRequest(config)

// 	// Convert struct to JSON
// 	jsonRequestBody, err := json.Marshal(requestBodyStruct)
// 	if err != nil {
// 		t.Fatalf("Failed to marshal request body: %v", err)
// 	}

// 	// Set up the HTTP request
// 	req, err := http.NewRequest("POST", paypalEndpoint, bytes.NewBuffer(jsonRequestBody))
// 	if err != nil {
// 		t.Fatalf("Failed to create a new request: %v", err)
// 	}

// 	// Set headers, including the bearer token
// 	req.Header.Set("Content-Type", "application/json")
// 	req.Header.Set("PayPal-Request-Id", "7b92603e-77ed-4896-8e78-5dea2050476a") // Replace with actual request id or generate one
// 	req.Header.Set("Authorization", bearerToken)                                // Replace with your actual bearer token

// 	// Send the request
// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		t.Fatalf("Failed to send request to PayPal API: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	bodyBytes, _ := ioutil.ReadAll(resp.Body)
// 	t.Logf("Response body: %s", bodyBytes)

// 	// Check if the response status is as expected
// 	if resp.StatusCode != http.StatusOK {
// 		t.Errorf("Expected status code %d, got %d", http.StatusCreated, resp.StatusCode)
// 	}
// }

func TestRequestPaypalNoProxy(t *testing.T) {
	const realEndpoint = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
	const realPaypalRequestID = "7b92603e-77ed-4896-8e78-5dea2050476a" // you may want to generate a new ID every time

	config := &PaypalConfig{
		ReferenceID: "default",
		AmountValue: "100.00",
		ReturnURL:   "https://example.com/return",
		CancelURL:   "https://example.com/cancel",
	}

	err := RequestPaypalNoProxy(realEndpoint, realPaypalRequestID, bearerToken, config)
	if err != nil {
		t.Fatalf("PostToPaypal failed: %v", err)
	}
}

func BenchmarkRequestPaypalNoProxy(b *testing.B) {
	const realEndpoint = "https://api-m.sandbox.paypal.com/v2/checkout/orders"
	const realPaypalRequestID = "7b92603e-77ed-4896-8e78-5dea2050476a" // in a real-world scenario, this might be dynamic or randomized

	config := &PaypalConfig{
		ReferenceID: "default",
		AmountValue: "100.00",
		ReturnURL:   "https://example.com/return",
		CancelURL:   "https://example.com/cancel",
	}

	b.ResetTimer() // Resetting timer to exclude setup time

	for i := 0; i < b.N; i++ {
		err := RequestPaypalNoProxy(realEndpoint, realPaypalRequestID, bearerToken, config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

package credentials

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type ProverCredential struct {
	ResourceURL     string
	TokenURL        string
	ClientID        string
	ClientSecret    string
	AccessToken     string
	UrlPrivateParts string
}

type CredsClient struct {
	Cred     ProverCredential
	CredName string
}

func NewCredsClient(credName string) (*CredsClient, error) {

	// init cc
	cc := new(CredsClient)
	cc.CredName = credName

	// parse json file
	jsonFile, err := os.Open("prover/credentials/" + credName + ".json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer jsonFile.Close()

	// parse json
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &cc.Cred)

	return cc, nil
}

func (cc *CredsClient) RequestToken() error {

	// Generated by curl-to-Go: https://mholt.github.io/curl-to-go

	// curl -v POST https://api.sandbox.paypal.com/v1/oauth2/token \                                                                          ~/Documents/coding/play/curlGo
	//   -H "Accept: application/json" \
	//   -H "Accept-Language: en_US" \
	//   -u "AUv8rrc_P-EbP2E0mpb49BV7rFt3Usr-vdUZO8VGOnjRehGHBXkSzchr37SYF2GNdQFYSp72jh5QUhzG:EMnAWe06ioGtouJs7gLYT9chK9-2jJ--7MKRXpI8FesmY_2Kp-d_7aCqff7M9moEJBvuXoBO4clKtY0v" \
	//   -d "grant_type=client_credentials"

	params := url.Values{}
	params.Add("grant_type", `client_credentials`)
	body := strings.NewReader(params.Encode())

	req, err := http.NewRequest("POST", cc.Cred.TokenURL, body)
	if err != nil {
		log.Println("http.NewRequest error:", err)
		return err
	}
	req.SetBasicAuth(cc.Cred.ClientID, cc.Cred.ClientSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en_US")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("http.DefaultClient error:", err)
		return err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return err
	}
	// fmt.Println(string(respBody))

	// extract access_token
	re := regexp.MustCompile(`"access_token":"(.*)"`)
	match := re.FindStringSubmatch(string(respBody))

	// fmt.Println(strings.Split(match[0], "\":\"")[1])
	access_token := strings.Split(strings.Split(match[0], "\":\"")[1], "\"")[0]
	// fmt.Println(access_token)

	// overwrite old value
	cc.Cred.AccessToken = access_token

	// lower part commented out as same functionality implemented in SetOrder function which is called right afterwards in commands/cmd_prover.go

	// write access token to credentials file
	// s, err := json.MarshalIndent(cc.Cred, "", "\t");
	// if err != nil {
	// log.Println("json.MashalIndent() error:", err)
	// return err
	// }

	// err = ioutil.WriteFile("prover/credentials/"+cc.CredName+".json", s, 0644)
	// if err != nil {
	// log.Println("ioutil.WriteFile error:", err)
	// return err
	// }

	return nil
}

func (cc *CredsClient) SetOrder() error {

	// perform request to create order identifier which can later be queried
	// url := "https://api-m.sandbox.paypal.com/v2/checkout/orders"
	url := cc.Cred.ResourceURL
	method := "POST"

	payload := strings.NewReader(`{
    "intent": "CAPTURE",
    "purchase_units": [
        {
            "items": [
                {
                    "name": "T-Shirt",
                    "description": "Green XL",
                    "quantity": "1",
                    "unit_amount": {
                        "currency_code": "USD",
                        "value": "100.00"
                    }
                }
            ],
            "amount": {
                "currency_code": "USD",
                "value": "100.00",
                "breakdown": {
                    "item_total": {
                        "currency_code": "USD",
                        "value": "100.00"
                    }
                }
            }
        }
    ],
    "application_context": {
        "return_url": "https://example.com/return",
        "cancel_url": "https://example.com/cancel"
    }
}`)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		log.Println("http.NewRequest() error:", err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Prefer", "return=representation")
	// req.Header.Add("PayPal-Request-Id", "2dc7067a-3c6f-4851-abe2-10c04ba3595f")
	//req.Header.Add("Authorization", "Bearer A21AAIRup8fuM-c9aop0sUVg4xwCWV46Lt0mHO-6RWmzxOuMcjoRKeJ7suUGDqbzBSy5cBlSx9aKBD550Bm3WMznmGqjXtj2A")
	req.Header.Add("Authorization", "Bearer "+cc.Cred.AccessToken)

	res, err := client.Do(req)
	if err != nil {
		log.Println("client.Do() error:", err)
		return err
	}
	defer res.Body.Close()

	respBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println("ioutil.ReadAll() error:", err)
		return err
	}
	// fmt.Println(string(body))

	// regex extract to get order identifier
	re := regexp.MustCompile(`"id":"(.*)"`)
	match := re.FindStringSubmatch(string(respBody))

	order_id := strings.Split(strings.Split(match[0], "\":\"")[1], "\"")[0]

	cc.Cred.UrlPrivateParts = order_id

	// write URL private parts to credentials file
	s, err := json.MarshalIndent(cc.Cred, "", "\t")
	if err != nil {
		log.Println("json.MashalIndent() error:", err)
		return err
	}

	err = ioutil.WriteFile("prover/credentials/"+cc.CredName+".json", s, 0644)
	if err != nil {
		log.Println("ioutil.WriteFile error:", err)
		return err
	}

	return nil
}

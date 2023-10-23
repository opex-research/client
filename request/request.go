package request

import (
	"bufio"
	tls "client/tls-fork"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"

	// "crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

type RequestTLS struct {
	ServerDomain    string
	ServerPath      string
	ProxyURL        string
	UrlPrivateParts string
	AccessToken     string
	StorageLocation string
}

type RequestData struct {
	secrets   map[string][]byte
	recordMap map[string]tls.RecordMeta
}

func NewRequest(serverDomain string, serverPath string, proxyURL string) RequestTLS {
	return RequestTLS{
		ServerDomain:    serverDomain,
		ServerPath:      serverPath, // "testserver.origodata.io"
		ProxyURL:        proxyURL,
		UrlPrivateParts: "",
		AccessToken:     "",
		StorageLocation: "./local_storage/",
	}
}

func (r *RequestTLS) Store(data RequestData) error {
	jsonData := make(map[string]map[string]string)
	jsonData["keys"] = make(map[string]string)

	for k, v := range data.secrets {
		jsonData["keys"][k] = hex.EncodeToString(v)
	}
	for k, v := range data.recordMap {
		jsonData[k] = make(map[string]string)
		jsonData[k]["typ"] = v.Typ
		jsonData[k]["additionalData"] = hex.EncodeToString(v.AdditionalData)
		jsonData[k]["payload"] = hex.EncodeToString(v.Payload)
		jsonData[k]["ciphertext"] = hex.EncodeToString(v.Ciphertext)
	}

	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = ioutil.WriteFile(r.StorageLocation+"session_params_13.json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.WriteFile")
	}
	return err
}

func (r *RequestTLS) Call(hsOnly bool) (RequestData, error) {

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

	// local server testing settings
	if r.ServerDomain == "localhost" {
		PathCaCrt := "certs/certificates/ca.crt"

		// set up cert verification
		caCert, _ := ioutil.ReadFile(PathCaCrt)
		caCertPool, _ := x509.SystemCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		config.RootCAs = caCertPool

		r.ServerDomain += ":8081"
	}

	// measure start time
	start := time.Now()

	// tls connection
	conn, err := tls.Dial("tcp", r.ProxyURL, config)
	if err != nil {
		log.Error().Err(err).Msg("tls.Dial()")
		return RequestData{}, err
	}
	defer conn.Close()

	// tls handshake time
	elapsed := time.Since(start)
	log.Debug().Str("time", elapsed.String()).Msg("client tls handshake took.")
	// state := conn.ConnectionState()

	// return here if handshakeOnly flag set
	if hsOnly {
		return RequestData{}, nil
	}

	// server settings
	serverURL := "https://" + r.ServerDomain + r.ServerPath
	if r.UrlPrivateParts != "" {
		serverURL += r.UrlPrivateParts
	}

	// measure request-response roundtrip
	start = time.Now()

	// build request
	request, _ := http.NewRequest(http.MethodGet, serverURL, nil)
	request.Close = false

	// request headers
	request.Header.Set("Content-Type", "application/json")
	if r.AccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+r.AccessToken)
	}

	// Here's the new code to add the padding
	dummyBuffer := bufio.NewWriter(nil)
	request.Write(dummyBuffer)
	requestSize := dummyBuffer.Buffered()

	paddingSize := 2048 - requestSize

	if paddingSize > 0 {
		padding := strings.Repeat("a", paddingSize)
		request.Header.Set("X-Dummy-Padding", padding)
	}

	// initialize connection buffers
	bufr := bufio.NewReader(conn)
	bufw := bufio.NewWriter(conn)

	// write request to connection buffer
	err = request.Write(bufw)
	if err != nil {
		log.Error().Err(err).Msg("request.Write(bufw)")
		return RequestData{}, err
	}

	requestSize = bufw.Buffered()
	log.Debug().Int("size", requestSize).Msg("Byte size of the request.")

	// writes buffer data into connection io.Writer
	err = bufw.Flush()
	if err != nil {
		log.Error().Err(err).Msg("bufw.Flush()")
		return RequestData{}, err
	}

	// read response
	resp, err := http.ReadResponse(bufr, request)
	if err != nil {
		log.Error().Err(err).Msg("http.ReadResponse(bufr, request)")
		return RequestData{}, err
	}
	defer resp.Body.Close()

	// Create a JSON file in local_storage directory
	outFile, err := os.Create("local_storage/api_response/response.json")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create file")
		return RequestData{}, err
	}
	defer outFile.Close()

	// Copy the HTTP response body (in JSON format) to the file
	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to write response to file")
		return RequestData{}, err
	}

	// reads response body
	msg, _ := ioutil.ReadAll(resp.Body)
	log.Trace().Msg("response data:")
	log.Trace().Msg(string(msg))

	// catch time
	elapsed = time.Since(start)
	log.Debug().Str("time", elapsed.String()).Msg("client request-response roundtrip took.")

	// access to recorded session data
	return RequestData{
		secrets:   conn.GetSecretMap(),
		recordMap: conn.GetRecordMap(),
	}, nil
}

package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/rs/zerolog/log"
)

type CombinedData struct {
	KDCShared        map[string]interface{} `json:"kdc_shared"`
	RecordTagPublic  map[string]interface{} `json:"recordtag_public"`
	RecordDataPublic map[string]interface{} `json:"recorddata_public"`
	KDCPublicInput   map[string]interface{} `json:"kdc_public_input"`
}

func ReadJSONFile(filename string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var jsonData map[string]interface{}
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return nil, err
	}
	return jsonData, nil
}

func SendCombinedDataToProxy(endpoint string, proxyServerURL string, combinedData *CombinedData) error {
	jsonData, err := json.Marshal(combinedData)
	if err != nil {
		return err
	}

	// Log the number of bytes being sent
	log.Debug().Int("bytesSent", len(jsonData)).Msg("Total postprocessing bytes sent to proxy.")

	url := fmt.Sprintf("http://%s/%s", proxyServerURL, endpoint)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Debug().Int("bytesReceived", len(body)).Msg("Total postprocessing bytes received from proxy. (Includes prover key)")

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed request: %s", body)
	}

	// Write received data to a file
	pkPath := "./local_storage/circuits/proof.pk"
	if err := os.WriteFile(pkPath, body, 0644); err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}

	return nil
}

func SendProofToProxy(endpoint string, proxyServerURL string, proofFilePath string) (bool, error) {
	// Read the proof file
	proofData, err := os.ReadFile(proofFilePath)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to read proof file: %s", proofFilePath)
		return false, err
	}

	// Log the number of bytes being sent
	log.Debug().Int("bytesSent", len(proofData)).Msg("Total size of proof sent to proxy.")

	url := fmt.Sprintf("http://%s%s", proxyServerURL, endpoint)

	// Create a new request with the proof data
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(proofData))
	if err != nil {
		log.Error().Err(err).Msg("Failed to create new request.")
		return false, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send request to proxy")
		return false, err
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response body from proxy")
		return false, err
	}

	log.Debug().Int("bytesReceived", len(body)).Msg("Total bytes received from proxy in response to the proof.")

	// Check response status
	if resp.StatusCode != http.StatusOK {
		log.Error().Msgf("Proxy responded with status: %s. Message: %s", resp.Status, string(body))
		return false, fmt.Errorf("Proxy error: %s", string(body))
	}

	return true, nil
}

func ReadM(filePath string) (map[string]string, error) {

	// open file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return nil, err
	}
	defer file.Close()

	// read in data
	data, err := io.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("io.ReadAll(file)")
		return nil, err
	}

	// parse json
	var objmap map[string]string
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return nil, err
	}

	return objmap, nil
}

func ReadMM(filePath string) (map[string]string, error) {

	// open file
	file, err := os.Open(filePath)
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return nil, err
	}
	defer file.Close()

	// read in data
	data, err := io.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("io.ReadAll(file)")
		return nil, err
	}

	// parse json
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return nil, err
	}

	// catch server record data
	innerMapFinal := make(map[string]string)
	for _, v := range objmap {

		// inner map parsing
		innerMap := make(map[string]string)
		err = json.Unmarshal(v, &innerMap)
		if err != nil {
			log.Error().Err(err).Msg("json.Unmarshal(v, &innerMap)")
			return nil, err
		}

		// copy
		for k2, v2 := range innerMap {
			innerMapFinal[k2] = v2
		}
	}

	return innerMapFinal, nil
}

func StoreM(jsonData map[string]string, filename string) error {

	file, err := json.MarshalIndent(jsonData, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}
	err = os.WriteFile("./local_storage/"+filename+".json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
		return err
	}
	return nil
}

func StoreMM(mapmap map[string]map[string]string, filename string) error {

	file, err := json.MarshalIndent(mapmap, "", " ")
	if err != nil {
		log.Error().Err(err).Msg("json.MarshalIndent")
		return err
	}

	err = os.WriteFile("./local_storage/"+filename+".json", file, 0644)
	if err != nil {
		log.Error().Err(err).Msg("os.WriteFile")
		return err
	}
	return nil
}

// serialize gnark object to given file
func Serialize(gnarkObject io.WriterTo, fileName string) {
	f, err := os.Create(fileName)
	if err != nil {
		log.Error().Err(err).Msg("os.Create(fileName)")
	}

	_, err = gnarkObject.WriteTo(f)
	if err != nil {
		log.Error().Err(err).Msg("gnarkObject.WriteTo(f)")
	}
}

// deserialize gnark object from given file
func Deserialize(gnarkObject io.ReaderFrom, fileName string) {
	f, err := os.Open(fileName)
	if err != nil {
		log.Error().Err(err).Msg("os.Open(fileName)")
	}

	_, err = gnarkObject.ReadFrom(f)
	if err != nil {
		log.Error().Err(err).Msg("gnarkObject.ReadFrom(f)")
	}
}

// debug function to check if serialization and deserialization work
func CheckSum(gnarkObject io.WriterTo, objName string) []byte {

	// compute hash of bytes
	buf := new(bytes.Buffer)
	_, err := gnarkObject.WriteTo(buf)
	if err != nil {
		log.Error().Err(err).Msg("gnarkObject.WriteTo(buf)")
	}

	hash := md5.Sum(buf.Bytes())
	log.Debug().Str("md5", hex.EncodeToString(hash[:])).Msg("checkSum of " + objName)

	return buf.Bytes()
}

func ZkStats() error {

	// proof file
	filename1 := "oracle_groth16.proof"
	f1, err := getFileInfo("./local_storage/circuits/" + filename1)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename1+" is %d bytes long.\n", f1.Size())

	// compiled constraint system
	filename2 := "oracle_groth16.ccs"
	f2, err := getFileInfo("./local_storage/circuits/" + filename2)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename2+" is %d bytes long.\n", f2.Size())

	// prover keys
	filename3 := "oracle_groth16.pk"
	f3, err := getFileInfo("./local_storage/circuits/" + filename3)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename3+" is %d bytes long.\n", f3.Size())

	// verifier keys
	filename4 := "oracle_groth16.vk"
	f4, err := getFileInfo("./local_storage/circuits/" + filename4)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename4+" is %d bytes long.\n", f4.Size())

	// public witness data
	filename5 := "oracle.pubwit"
	f5, err := getFileInfo("./local_storage/circuits/" + filename5)
	if err != nil {
		log.Error().Err(err).Msg("getFileInfo")
		return err
	}
	fmt.Printf("The file "+filename5+" is %d bytes long.\n", f5.Size())

	return nil
}

// func TrascriptStats() error {

// 	filename1 := "ClientSentRecords.raw"
// 	f1, err := getFileInfo("./local_storage/" + filename1)
// 	if err != nil {
// 		log.Error().Err(err).Msg("getFileInfo")
// 		return err
// 	}
// 	fmt.Printf("The file "+filename1+" is %d bytes long.\n", f1.Size())

// 	filename2 := "ServerSentRecords.raw"
// 	f2, err := getFileInfo("./local_storage/" + filename2)
// 	if err != nil {
// 		log.Error().Err(err).Msg("getFileInfo")
// 		return err
// 	}
// 	fmt.Printf("The file "+filename2+" is %d bytes long.\n", f2.Size())

// 	return nil
// }

func getFileInfo(filePath string) (os.FileInfo, error) {
	f1, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f1.Close()

	fi, err := f1.Stat()
	if err != nil {
		return nil, err
	}
	return fi, nil
}

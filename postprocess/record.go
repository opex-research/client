package postprocess

import (
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"

	p "client/policy"
	u "client/utils"

	"github.com/rs/zerolog/log"
)

// TODO: move to config, improve policy handling
var serverPolicyPaths = map[string]string{
	"local":  "policy/policy.json",
	"paypal": "policy/policy_paypal.json",
}

func ParsePlaintextWithPolicy(server string, rps map[string]map[string]string) error {

	// init values
	found := false

	// get policy
	policy, err := p.New(serverPolicyPaths[server])
	log.Debug().Msgf("Policy: %s", policy)

	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize policy")
		return err
	}

	jsonData := make(map[string]string)
	jsonData2 := make(map[string]string)

	// parse plaintext chunks
	// record has SR content found in session_params_13
	for _, record := range rps {

		// loop over plaintext 16b chunks
		plaintextBytes, err := hex.DecodeString(record["payload"])
		if err != nil {
			log.Error().Err(err).Msg("Failed to decode hex for record payload")
			return err
		}

		plaintext := string(plaintextBytes)

		log.Debug().Msgf("Processing plaintext: %s", plaintext)

		// to capture ciphertext_chunks if match found
		ciphertextBytes, err := hex.DecodeString(record["ciphertext"])
		if err != nil {
			log.Error().Err(err).Msg("Failed to decode hex for record ciphertext")
			return err
		}

		// check if substring exists
		var startIdxAreaOfInterest, endIdxAreaOfInterest, chunkIndex int
		found = strings.Contains(plaintext, policy.Substring)
		if found {
			startIdxAreaOfInterest = strings.Index(plaintext, policy.Substring)
			endIdxAreaOfInterest = startIdxAreaOfInterest + len(policy.Substring) + policy.ValueStartIdxAfterSS + policy.ValueLength
		} else {
			log.Error().Msg("Substring match not found in plaintext")
			continue // Skip to the next record in rps
		}

		// area of interest used to identify the number of chunks that must be decrypted
		numb_chunks := len(plaintextBytes) / 16
		sizeAreaOfInterest := endIdxAreaOfInterest - startIdxAreaOfInterest
		for i := 0; i < numb_chunks; i++ {
			chunkEnd := (i + 1) * 16
			if chunkEnd >= startIdxAreaOfInterest {
				// set chunk index
				chunkIndex = i
				// exist loop
				i = numb_chunks
			}
		}
		number_chunks := (((startIdxAreaOfInterest - (chunkIndex * 16)) + sizeAreaOfInterest) / 16) + 1
		start_idx_chunks := startIdxAreaOfInterest - (chunkIndex * 16)

		// public input for record data proof
		jsonData["chunk_index"] = strconv.Itoa(chunkIndex + 2)
		jsonData["substring"] = policy.Substring
		jsonData["substring_start_idx"] = strconv.Itoa(startIdxAreaOfInterest)
		jsonData["number_chunks"] = strconv.Itoa(number_chunks)
		jsonData["size_area_of_interest"] = strconv.Itoa(sizeAreaOfInterest)
		jsonData["size_value"] = strconv.Itoa(policy.ValueLength)
		jsonData["cipher_chunks"] = hex.EncodeToString(ciphertextBytes[chunkIndex*16 : (chunkIndex+number_chunks)*16])
		jsonData2["plain_chunks"] = hex.EncodeToString(plaintextBytes[chunkIndex*16 : (chunkIndex+number_chunks)*16])
		// chunk level substring start index
		jsonData["substring_start"] = strconv.Itoa(start_idx_chunks)
		jsonData["substring_end"] = strconv.Itoa(len(policy.Substring) + start_idx_chunks)
		jsonData["value_start"] = strconv.Itoa(start_idx_chunks + sizeAreaOfInterest - policy.ValueLength - 1)
		jsonData["value_end"] = strconv.Itoa(start_idx_chunks + sizeAreaOfInterest - 1)
		log.Debug().Str("string", string(plaintextBytes[startIdxAreaOfInterest:startIdxAreaOfInterest+sizeAreaOfInterest])).Msg("area of interest")
		log.Debug().Str("plain_chunks", string(policy.Substring)).Msg("Logged plain_chunks.")
		log.Debug().Str("plain_chunks", string(policy.ValueStartIdxAfterSS)).Msg("Logged plain_chunks.")
		log.Debug().Str("plain_chunks", string(policy.ValueLength)).Msg("Logged plain_chunks.")
	}

	err = u.StoreM(jsonData, "recorddata_public_input")
	if err != nil {
		return err
	}

	err = u.StoreM(jsonData2, "recorddata_private_input")
	if err != nil {
		return err
	}

	return nil
}

func RecordTagZkInput(sParams map[string]string, rps map[string]map[string]string) error {

	// get data and init aes
	keyBytes, _ := hex.DecodeString(sParams["keySapp"])
	ivBytes, _ := hex.DecodeString(sParams["ivSapp"])
	aes, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Error().Err(err).Msg("aes.NewCipher(key)")
		return err
	}

	// store data
	// jsonDataPrivate := make(map[string]map[string]string)
	jsonDataPublic := make(map[string]map[string]string)

	for sequence := range rps {

		// collects output
		jsonData := make(map[string]string)

		// gcm_nonce is iv || counter=0
		// todo: concatenate sequence number behind ivBytes in gcm_nonce
		var gcm_nonce [16]byte
		if sequence == "0000000000000000" {
			copy(gcm_nonce[:], ivBytes)
		}

		// must be set if nonce comes in default size equal to 12
		gcm_nonce[15] = 1
		// fmt.Println("gcm_nonce:", gcm_nonce, hex.EncodeToString(gcm_nonce[:]))

		// compute encrypted counter block zero vector (ECB0)
		// ECB0 depends on key+iv and counter=0
		cipherdata := make([]byte, 16)
		aes.Encrypt(cipherdata, gcm_nonce[:])
		jsonData["ECB0"] = hex.EncodeToString(cipherdata)

		// compute encrypted counter block key (ECBK) by encryption zero vector
		var ecbk [16]byte
		// fmt.Println("ecbk:", ecbk[:], hex.EncodeToString(ecbk[:]))
		aes.Encrypt(ecbk[:], ecbk[:])

		jsonData["ECBK"] = hex.EncodeToString(ecbk[:])

		jsonDataPublic[sequence] = jsonData
	}

	err = u.StoreMM(jsonDataPublic, "recordtag_public_input")
	if err != nil {
		log.Error().Err(err).Msg("u.StoreMM")
		return err
	}

	return nil
}

func ShowPlaintext(rps map[string]map[string]string) {
	for _, v := range rps {
		log.Debug().Msg("---record data---")
		payloadBytes, _ := hex.DecodeString(v["payload"])
		log.Debug().Msg(string(payloadBytes))
	}
}

func ReadServerParams() (map[string]string, error) {

	// open file
	file, err := os.Open("./local_storage/skdc_params.json")
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

func ReadServerRecords() (map[string]map[string]string, error) {

	// open file
	file, err := os.Open("./local_storage/session_params_13.json")
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
	recordPerSequence := make(map[string]map[string]string)
	for k, v := range objmap {
		if k != "keys" {

			valuesOfInterest := make(map[string]string)

			// parse records
			keyValues := make(map[string]string)
			err = json.Unmarshal(v, &keyValues)
			if err != nil {
				log.Error().Err(err).Msg("json.Unmarshal(v, &keyValues)")
				return nil, err
			}

			// catch for sever record layer traffic
			if keyValues["typ"] == "SR" {
				valuesOfInterest["ciphertext"] = keyValues["ciphertext"]
				valuesOfInterest["recordHashSF"] = k
				valuesOfInterest["payload"] = keyValues["payload"]

				// record layer data
				recordPerSequence[k] = valuesOfInterest
			}

		}
	}

	// prover post processing depends on secrets only
	return recordPerSequence, nil
}

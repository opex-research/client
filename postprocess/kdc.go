package postprocess

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	tls "client/tls-fork"
	u "client/utils"

	"github.com/rs/zerolog/log"
)

// function generates public input required to verify zk circuit
// or necessary to compute verification variables on the verifier side
// e.g. intermediateHashHSopad is public input to the zk circuit
// and must be shared to compute variables to verify SHTS
func KdcShared(toBshared, sdataMap, cdataMap map[string]string) error {

	// fill data structure
	jsonData := make(map[string]string)
	jsonData["SHTSin"] = sdataMap["SHTSin"]
	jsonData["intermediateHashHSopad"] = sdataMap["intermediateHashHSopad"]
	jsonData["intermediateHashdHSipad"] = sdataMap["intermediateHashdHSipad"]
	jsonData["intermediateHashMSipad"] = sdataMap["intermediateHashMSipad"]
	jsonData["intermediateHashSATSipad"] = sdataMap["intermediateHashSATSipad"]
	jsonData["intermediateHashCATSipad"] = cdataMap["intermediateHashCATSipad"]
	jsonData["hashKeyCapp"] = cdataMap["hashKeyCapp"]
	jsonData["hashIvCapp"] = cdataMap["hashIvCapp"]
	jsonData["hashKeySapp"] = sdataMap["hashKeySapp"]
	jsonData["hashIvSapp"] = sdataMap["hashIvSapp"]
	jsonData["SHTS"] = toBshared["SHTS"]

	// store data
	err := u.StoreM(jsonData, "kdc_shared")
	if err != nil {
		log.Error().Msg("u.StoreM")
		return err
	}
	return nil
}

func KdcPublicInput(sdataMap, cdataMap map[string]string) error {

	// fill data structure
	jsonData := make(map[string]string)
	jsonData["intermediateHashHSopad"] = sdataMap["intermediateHashHSopad"]
	jsonData["MSin"] = sdataMap["MSin"]
	jsonData["SATSin"] = sdataMap["SATSin"]
	jsonData["CATSin"] = cdataMap["CATSin"]
	jsonData["tkSAPPin"] = sdataMap["tkSAPPin"]
	jsonData["tkCAPPin"] = cdataMap["tkCAPPin"]
	// iv related values
	// final ivs can be made public for authtag circuit computation
	// jsonData["ivSAPPin"] = sdataMap["ivSAPPin"]
	// jsonData["ivCAPPin"] = cdataMap["ivCAPPin"]
	jsonData["ivSapp"] = sdataMap["ivSapp"]
	jsonData["ivCapp"] = cdataMap["ivCapp"]
	// key hashes
	// required for the case where circuit is decoupled
	jsonData["hashKeySapp"] = sdataMap["hashKeySapp"]
	jsonData["hashKeyCapp"] = cdataMap["hashKeyCapp"]

	// store data
	err := u.StoreM(jsonData, "kdc_public_input")
	if err != nil {
		log.Error().Msg("u.StoreM")
		return err
	}
	return nil
}

func KdcPrivateInput(sdataMap map[string]string) error {

	// fill data structure
	jsonData := make(map[string]string)
	jsonData["dHSin"] = sdataMap["dHSin"]

	// store data
	err := u.StoreM(jsonData, "kdc_private_input")
	if err != nil {
		log.Error().Msg("u.StoreM")
		return err
	}
	return nil
}

func DeriveKeyIvSATS(toBshared map[string]string) (map[string]string, error) {

	// derive sats values
	HS, _ := hex.DecodeString(toBshared["HS"])
	H3, _ := hex.DecodeString(toBshared["H3"])
	H2, _ := hex.DecodeString(toBshared["H2"])

	intermediateHashHSipad := tls.PIntermediateHashHSipad(HS)
	intermediateHashHSopad := tls.ZKIntermediateHashHSopad(HS)

	SHTSin := tls.PSHTSin(intermediateHashHSipad, H2)

	// check if SHTSin maps to correct SHTS
	// SHTS := tls.VSHTS(intermediateHashHSopad, SHTSin)
	// fmt.Println("SHTS:", hex.EncodeToString(SHTS))

	dHSin := tls.PdHSin(intermediateHashHSipad)
	dHS := tls.ZKdHS(intermediateHashHSopad, dHSin)

	intermediateHashdHSipad := tls.PIntermediateHashdHSipad(dHS)
	MSin := tls.VMSin(intermediateHashdHSipad)
	MS := tls.ZKMS(dHS, MSin)

	intermediateHashMSipad := tls.PIntermediateHashMSipad(MS)
	SATSin := tls.VXATSin(intermediateHashMSipad, H3, "s ap traffic")
	SATS := tls.ZKXATS(MS, SATSin)
	// fmt.Println("SATS:", hex.EncodeToString(SATS))

	intermediateHashSATSipad := tls.PIntermediateHashXATSipad(SATS)
	tkSAPPin := tls.VTkXAPPin(intermediateHashSATSipad)
	intermediateHashSATSopad := tls.ZKIntermediateHashXATSopad(SATS)
	key := tls.ZKtkXAPP(intermediateHashSATSopad, tkSAPPin)
	IVin := tls.VIVin(intermediateHashSATSipad)
	iv := tls.PIV(intermediateHashSATSopad, IVin)

	// fill data structure
	jsonData := make(map[string]string)
	jsonData["intermediateHashHSipad"] = hex.EncodeToString(intermediateHashHSipad)
	jsonData["intermediateHashHSopad"] = hex.EncodeToString(intermediateHashHSopad)
	jsonData["dHSin"] = hex.EncodeToString(dHSin)
	jsonData["intermediateHashdHSipad"] = hex.EncodeToString(intermediateHashdHSipad)
	jsonData["MSin"] = hex.EncodeToString(MSin)
	jsonData["intermediateHashMSipad"] = hex.EncodeToString(intermediateHashMSipad)
	jsonData["SATSin"] = hex.EncodeToString(SATSin)
	jsonData["SHTSin"] = hex.EncodeToString(SHTSin)
	jsonData["intermediateHashSATSipad"] = hex.EncodeToString(intermediateHashSATSipad)
	jsonData["tkSAPPin"] = hex.EncodeToString(tkSAPPin)
	jsonData["ivSAPPin"] = hex.EncodeToString(IVin)
	jsonData["keySapp"] = hex.EncodeToString(key)
	jsonData["ivSapp"] = hex.EncodeToString(iv)
	jsonData["hashKeySapp"] = hex.EncodeToString(tls.Sum256(key))
	jsonData["hashIvSapp"] = hex.EncodeToString(tls.Sum256(iv))

	// store data
	err := u.StoreM(jsonData, "skdc_params")
	if err != nil {
		log.Error().Msg("u.StoreM")
		return nil, err
	}
	return jsonData, nil
}

func DeriveKeyIvCATS(toBshared map[string]string) (map[string]string, error) {

	// derive sats values
	HS, _ := hex.DecodeString(toBshared["HS"])
	H3, _ := hex.DecodeString(toBshared["H3"])

	intermediateHashHSipad := tls.PIntermediateHashHSipad(HS)  // prover
	intermediateHashHSopad := tls.ZKIntermediateHashHSopad(HS) // zk
	dHSin := tls.PdHSin(intermediateHashHSipad)                // verifier
	dHS := tls.ZKdHS(intermediateHashHSopad, dHSin)            // zk

	intermediateHashdHSipad := tls.PIntermediateHashdHSipad(dHS) // prover
	MSin := tls.VMSin(intermediateHashdHSipad)                   // verifier
	MS := tls.ZKMS(dHS, MSin)                                    // zk

	intermediateHashMSipad := tls.PIntermediateHashMSipad(MS)         // prover
	CATSin := tls.VXATSin(intermediateHashMSipad, H3, "c ap traffic") // verifier
	CATS := tls.ZKXATS(MS, CATSin)                                    // zk
	// fmt.Println("CATS:", hex.EncodeToString(CATS))

	intermediateHashCATSipad := tls.PIntermediateHashXATSipad(CATS)  // prover
	tkCAPPin := tls.VTkXAPPin(intermediateHashCATSipad)              // verifier
	intermediateHashCATSopad := tls.ZKIntermediateHashXATSopad(CATS) // zk
	key := tls.ZKtkXAPP(intermediateHashCATSopad, tkCAPPin)          // zk
	IVin := tls.VIVin(intermediateHashCATSipad)                      // verifier
	iv := tls.PIV(intermediateHashCATSopad, IVin)                    // prover

	// fill data structure
	jsonData := make(map[string]string)
	jsonData["intermediateHashHSipad"] = hex.EncodeToString(intermediateHashHSipad)
	jsonData["intermediateHashHSopad"] = hex.EncodeToString(intermediateHashHSopad)
	jsonData["dHSin"] = hex.EncodeToString(dHSin)
	jsonData["intermediateHashdHSipad"] = hex.EncodeToString(intermediateHashdHSipad)
	jsonData["CATSin"] = hex.EncodeToString(CATSin)
	jsonData["intermediateHashMSipad"] = hex.EncodeToString(intermediateHashMSipad)
	jsonData["intermediateHashCATSipad"] = hex.EncodeToString(intermediateHashCATSipad)
	jsonData["tkCAPPin"] = hex.EncodeToString(tkCAPPin)
	jsonData["ivCAPPin"] = hex.EncodeToString(IVin)
	jsonData["keyCapp"] = hex.EncodeToString(key)
	jsonData["ivCapp"] = hex.EncodeToString(iv)
	jsonData["hashKeyCapp"] = hex.EncodeToString(tls.Sum256(key))
	jsonData["hashIvCapp"] = hex.EncodeToString(tls.Sum256(iv))

	// store data
	err := u.StoreM(jsonData, "ckdc_params")
	if err != nil {
		log.Error().Msg("u.StoreM")
		return nil, err
	}
	return jsonData, nil
}

func ProcessSF(toBshared map[string]string) error {

	// compute missing values for key verification
	HS, _ := hex.DecodeString(toBshared["HS"])
	intermediateHashHSopad := tls.PIntermediateHashHSopad(HS)
	intermediateHashHSipad := tls.PIntermediateHashHSipad(HS)

	// add values to json map
	jsonData := make(map[string]string)
	jsonData["SHTS"] = toBshared["SHTS"]
	jsonData["H2"] = toBshared["H2"]
	jsonData["H3"] = toBshared["H3"]
	jsonData["H7"] = toBshared["H7"]
	jsonData["intermediateHashHSopad"] = hex.EncodeToString(intermediateHashHSopad)
	jsonData["intermediateHashHSipad"] = hex.EncodeToString(intermediateHashHSipad)
	jsonData["recordHashSF"] = toBshared["recordHashSF"]
	jsonData["additionalData"] = toBshared["additionalData"]
	jsonData["ciphertext"] = toBshared["ciphertext"]

	// store data
	err := u.StoreM(jsonData, "sf_public")
	if err != nil {
		log.Error().Msg("u.StoreM")
		return err
	}

	return nil
}

func Read() (map[string]string, error) {

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

	// process data
	// records := make(map[string]map[string]string)
	twoBshared := make(map[string]string)
	for k, v := range objmap {
		if k == "keys" {
			err = json.Unmarshal(v, &twoBshared)
			if err != nil {
				log.Error().Err(err).Msg("json.Unmarshal(v, &secrets)")
				return nil, err
			}
		} else {

			// parse records
			rm := make(map[string]string)
			err = json.Unmarshal(v, &rm)
			if err != nil {
				log.Error().Err(err).Msg("json.Unmarshal(v, &rm)")
				return nil, err
			}

			// catch SF record
			if rm["typ"] == "SF" {
				twoBshared["ciphertext"] = rm["ciphertext"]
				twoBshared["additionalData"] = rm["additionalData"]
				twoBshared["recordHashSF"] = k
			}
		}
	}

	// prover post processing depends on secrets only
	return twoBshared, nil
}

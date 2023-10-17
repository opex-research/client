package prove

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	u "client/utils"

	glibg "client/tls-zkp/circuits/gadgets"

	"github.com/rs/zerolog/log"

	"github.com/consensys/gnark-crypto/ecc"
	// "github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
)

func saveParamsToFile(params map[string]string) error {
	// Convert params into JSON formatted bytes
	data, err := json.MarshalIndent(params, "", "    ") // Indented for readability
	if err != nil {
		return err
	}

	// Create and open a new file for writing
	file, err := os.Create("./local_storage/final_params.json")
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the JSON data to the file
	_, err = file.Write(data)
	return err
}

func CircuitAssign(thresholdValue string) (frontend.Circuit, frontend.Circuit, error) {

	// read in data
	params, err := readOracleParams()
	if err != nil {
		log.Error().Msg("readOracleParams()")
		return nil, nil, err
	}

	// Save parameters to file
	err = saveParamsToFile(params)
	if err != nil {
		log.Error().Err(err).Msg("Error saving parameters to final_params.json.")
	}

	byteSlice, _ := hex.DecodeString(params["sequence_number"])
	sequenceNumberByteLen := len(byteSlice)

	// further preprocessing
	zeros := "00000000000000000000000000000000"
	ivCounter := addCounter(params["ivSapp"])
	log.Debug().Msgf("Converted threshold value: %v", ivCounter)
	newdHSin, dHSinByteLen := padDHSin(params["dHSin"])
	chunkIndex, _ := strconv.Atoi(params["chunk_index"])
	substringStart, _ := strconv.Atoi(params["substring_start"])
	substringEnd, _ := strconv.Atoi(params["substring_end"])
	valueStart, _ := strconv.Atoi(params["value_start"])
	valueEnd, _ := strconv.Atoi(params["value_end"])

	threshold, err := strconv.Atoi(thresholdValue)

	// Debug log the threshold value
	log.Debug().Msgf("Converted threshold value: %d", threshold)

	if err != nil {
		// handle the error appropriately, e.g., return or log it
		log.Error().Err(err).Msg("Error converting thresholdValue to int.")
		return nil, nil, err
	}

	// kdc to bytes
	byteSlice, _ = hex.DecodeString(params["intermediateHashHSopad"])
	intermediateHashHSopadByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["MSin"])
	MSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["SATSin"])
	SATSinByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["tkSAPPin"])
	tkSAPPinByteLen := len(byteSlice)
	// authtag to bytes
	byteSlice, _ = hex.DecodeString(ivCounter)
	ivCounterByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(zeros)
	zerosByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["ECB0"])
	ecb0ByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["ECBK"])
	ecbkByteLen := len(byteSlice)
	// record to bytes
	byteSlice, _ = hex.DecodeString(params["ivSapp"])
	ivByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["cipher_chunks"])
	chipherChunksByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(params["plain_chunks"])
	plainChunksByteLen := len(byteSlice)
	substringByteLen := len(params["substring"])

	log.Debug().Msgf("sequenceNumberAssign: %v", byteSlice)

	// witness definition kdc
	intermediateHashHSopadAssign := glibg.StrToIntSlice(params["intermediateHashHSopad"], true)
	dHSinAssign := glibg.StrToIntSlice(newdHSin, true)
	MSinAssign := glibg.StrToIntSlice(params["MSin"], true)
	SATSinAssign := glibg.StrToIntSlice(params["SATSin"], true)
	tkSAPPinAssign := glibg.StrToIntSlice(params["tkSAPPin"], true)
	// tkCommitAssign := u.StrToIntSlice(tkCommit, true)
	// witness definition authtag
	ivCounterAssign := glibg.StrToIntSlice(ivCounter, true)
	zerosAssign := glibg.StrToIntSlice(zeros, true)
	ecb0Assign := glibg.StrToIntSlice(params["ECB0"], true)
	ecbkAssign := glibg.StrToIntSlice(params["ECBK"], true)
	// witness definition record
	ivAssign := glibg.StrToIntSlice(params["ivSapp"], true)
	chipherChunksAssign := glibg.StrToIntSlice(params["cipher_chunks"], true)
	plainChunksAssign := glibg.StrToIntSlice(params["plain_chunks"], true)
	substringAssign := glibg.StrToIntSlice(params["substring"], false)
	sequenceNumberAssign := glibg.StrToIntSlice(params["sequence_number"], true)

	// witness values preparation
	assignment := glibg.Tls13OracleWrapper{
		// kdc params
		IntermediateHashHSopad: [32]frontend.Variable{},
		DHSin:                  [64]frontend.Variable{},
		MSin:                   [32]frontend.Variable{},
		SATSin:                 [32]frontend.Variable{},
		TkSAPPin:               [32]frontend.Variable{},
		// TkCommit:               [32]frontend.Variable{},
		// authtag params
		IvCounter: [16]frontend.Variable{},
		Zeros:     [16]frontend.Variable{},
		ECB0:      [16]frontend.Variable{},
		ECBK:      [16]frontend.Variable{},
		// record pararms
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		Iv:             [12]frontend.Variable{},
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		ChunkIndex:     chunkIndex,
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
		Threshold:      threshold,
		SequenceNumber: [8]frontend.Variable{},
	}

	// kdc assign
	for i := 0; i < intermediateHashHSopadByteLen; i++ {
		assignment.IntermediateHashHSopad[i] = intermediateHashHSopadAssign[i]
	}
	for i := 0; i < dHSinByteLen; i++ {
		assignment.DHSin[i] = dHSinAssign[i]
	}
	for i := 0; i < MSinByteLen; i++ {
		assignment.MSin[i] = MSinAssign[i]
	}
	for i := 0; i < SATSinByteLen; i++ {
		assignment.SATSin[i] = SATSinAssign[i]
	}
	for i := 0; i < tkSAPPinByteLen; i++ {
		assignment.TkSAPPin[i] = tkSAPPinAssign[i]
	}
	log.Debug().Msgf("ivCounterByteLen: %v", ivCounterByteLen)
	log.Debug().Msgf("ivCounterAssign: %v", ivCounterAssign)
	// authtag assign
	for i := 0; i < ivCounterByteLen; i++ {
		assignment.IvCounter[i] = ivCounterAssign[i]
	}
	for i := 0; i < zerosByteLen; i++ {
		assignment.Zeros[i] = zerosAssign[i]
	}
	for i := 0; i < ecbkByteLen; i++ {
		assignment.ECBK[i] = ecbkAssign[i]
	}
	for i := 0; i < ecb0ByteLen; i++ {
		assignment.ECB0[i] = ecb0Assign[i]
	}
	// record assign
	for i := 0; i < plainChunksByteLen; i++ {
		assignment.PlainChunks[i] = plainChunksAssign[i]
	}
	for i := 0; i < ivByteLen; i++ {
		assignment.Iv[i] = ivAssign[i]
	}
	for i := 0; i < chipherChunksByteLen; i++ {
		assignment.CipherChunks[i] = chipherChunksAssign[i]
	}
	for i := 0; i < substringByteLen; i++ {
		assignment.Substring[i] = substringAssign[i]
	}
	for i := 0; i < sequenceNumberByteLen; i++ {
		assignment.SequenceNumber[i] = sequenceNumberAssign[i]
	}

	// var circuit kdcServerKey
	circuit := glibg.Tls13OracleWrapper{
		PlainChunks:    make([]frontend.Variable, plainChunksByteLen),
		CipherChunks:   make([]frontend.Variable, chipherChunksByteLen),
		Substring:      make([]frontend.Variable, substringByteLen),
		SubstringStart: substringStart,
		SubstringEnd:   substringEnd,
		ValueStart:     valueStart,
		ValueEnd:       valueEnd,
	}

	log.Debug().Msgf("intermediateHashHSopadAssign: %v", intermediateHashHSopadAssign)
	log.Debug().Msgf("dHSinAssign: %v", dHSinAssign)
	log.Debug().Msgf("MSinAssign: %v", MSinAssign)
	log.Debug().Msgf("SATSinAssign: %v", SATSinAssign)
	log.Debug().Msgf("tkSAPPinAssign: %v", tkSAPPinAssign)
	log.Debug().Msgf("ivCounterAssign: %v", ivCounterAssign)
	log.Debug().Msgf("ecbkAssign: %v", ecbkAssign)
	log.Debug().Msgf("ecb0Assign: %v", ecb0Assign)
	log.Debug().Msgf("chipherChunksAssign: %v", chipherChunksAssign)
	log.Debug().Msgf("ivAssign: %v", ivAssign)
	log.Debug().Msgf("sequenceNumberAssign: %v", sequenceNumberAssign)

	return &circuit, &assignment, err
}

func readOracleParams() (map[string]string, error) {

	// to be returned
	finalMap := make(map[string]string)

	// read in kdc pub params
	kdc_pub, err := u.ReadM("./local_storage/kdc_public_input.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range kdc_pub {
		finalMap[k] = v
	}

	// read in kdc priv params
	kdc_priv, err := u.ReadM("./local_storage/kdc_private_input.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range kdc_priv {
		finalMap[k] = v
	}

	// read in authtag params
	tag_pub, err := u.ReadMM("./local_storage/recordtag_public_input.json")
	if err != nil {
		log.Error().Msg("u.ReadMM")
		return nil, err
	}

	// copy
	for k, v := range tag_pub {
		finalMap[k] = v
	}

	// read in record publ params
	record_pub, err := u.ReadM("./local_storage/recorddata_public_input.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range record_pub {
		finalMap[k] = v
	}

	// read in record private params
	record_priv, err := u.ReadM("./local_storage/recorddata_private_input.json")
	if err != nil {
		log.Error().Msg("u.ReadM")
		return nil, err
	}

	// copy
	for k, v := range record_priv {
		finalMap[k] = v
	}

	return finalMap, nil
}

// TODO - Add sequence number, currently hardcoded
func addCounter(iv string) string {
	// add counter to iv bytes
	var sb strings.Builder
	for i := 0; i < len(iv); i++ {
		sb.WriteString(string(iv[i]))
	}
	for i := 0; i < 7; i++ {
		sb.WriteString("0")
	}
	sb.WriteString("2")
	return sb.String()
}

func padDHSin(dHSin string) (string, int) {
	dHSSlice, _ := hex.DecodeString(dHSin)
	dHSinByteLen := len(dHSSlice)
	// add padding out of circuit
	pad := glibg.PadSha256(96)
	dHSinPadded := make([]byte, 32+len(pad))
	copy(dHSinPadded, dHSSlice)
	copy(dHSinPadded[32:], pad)
	newdHSin := hex.EncodeToString(dHSinPadded)
	dHSinByteLen += 32
	return newdHSin, dHSinByteLen
}

func ComputeProof(backend string, assignment frontend.Circuit) error {

	// generate witness
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Error().Msg("frontend.NewWitness")
		return err
	}

	switch backend {
	case "groth16":

		circuit, err := GetCircuit()
		if err != nil {
			log.Error().Msg("groth16 GetCircuit")
			return err
		}

		backend := "groth16"
		ccs, err := CompileCircuit(backend, circuit)
		if err != nil {
			log.Error().Msg("groth16 CompileCircuit")
			return err
		}

		pk := groth16.NewProvingKey(ecc.BN254)
		u.Deserialize(pk, "./local_storage/circuits/proof.pk")

		proof, err := groth16.Prove(ccs, pk, w)
		if err != nil {
			log.Error().Msg("groth16.Prove")
			return err
		}

		u.Serialize(proof, "./local_storage/circuits/oracle_"+backend+".proof")
	case "plonk":

		// TODO - Update for remote communication
		// In Plonk, we should be able to run the deterministic setup locally

		// read in values...
		ccs := plonk.NewCS(ecc.BN254)
		pk := plonk.NewProvingKey(ecc.BN254)
		// vk := plonk.NewVerifyingKey(ecc.BN254)
		// srs := kzg.NewSRS(ecc.BN254)
		u.Deserialize(ccs, "./local_storage/circuits/oracle_"+backend+".ccs")
		u.Deserialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		// u.Deserialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")
		// u.Deserialize(srs, "./local_storage/circuits/oracle_"+backend+".srs")

		proof, err := plonk.Prove(ccs, pk, w)
		if err != nil {
			log.Error().Msg("plonk.Prove")
			return err
		}
		u.Serialize(proof, "./local_storage/circuits/oracle_"+backend+".proof")

	case "plonkFRI":

	}
	return nil
}

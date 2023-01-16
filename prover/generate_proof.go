package prover

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"

	lp "github.com/anonymoussubmission001/origo/dependencies/ledger_policy"
	mtls "github.com/anonymoussubmission001/origo/dependencies/tls"
)

type Prover struct {
	Policy            lp.Policy
	Config            ProverConfig
	PolicyExtract     mtls.PolicyExtract
	PolicyFileName    string
	GeneratorFileName string
}

func NewProver(policyFileName string, generatorFileName string, configOnly bool) (*Prover, error) {

	// init prover
	prover := new(Prover)

	// TODO: fix hardcoded path
	// open policy and deserialize to struct
	if !configOnly {
		policyFile, err := os.Open("dependencies/ledger_policy/" + policyFileName + ".json")
		if err != nil {
			log.Println("os.Open() error", err)
			return nil, err
		}
		defer policyFile.Close()
		byteValue, _ := ioutil.ReadAll(policyFile)
		json.Unmarshal(byteValue, &prover.Policy)
	}

	prover.PolicyFileName = policyFileName
	prover.GeneratorFileName = generatorFileName

	// TODO: fix hardcoded path
	// open config and deserialize to struct
	configFile, err := os.Open("prover/config.json")
	if err != nil {
		log.Println("os.Open() error", err)
		return nil, err
	}
	defer configFile.Close()
	byteValue2, _ := ioutil.ReadAll(configFile)
	json.Unmarshal(byteValue2, &prover.Config)

	// read in extracted tls values (get deployment data)
	if !configOnly {
		extractFile, err := os.Open(prover.Config.StoragePath + "PolicyExtractJson.json")
		if err != nil {
			log.Println("os.Open() error", err)
			return nil, err
		}
		defer extractFile.Close()
		byteValue3, _ := ioutil.ReadAll(extractFile)
		json.Unmarshal(byteValue3, &prover.PolicyExtract)
	}

	return prover, nil
}

func (p *Prover) CompileCircuit() error {

	// shortening
	pe := p.PolicyExtract

	// parse policy extract values
	blockNr := strconv.Itoa(pe.EndBlockIdx - pe.StartBlockIdx)
	startBlockIdx := strconv.Itoa(pe.StartBlockIdx)
	keyValuePairLen := strconv.Itoa(pe.KeyValuePatternLength)
	offsetKeyValuePair := strconv.Itoa(pe.OffsetKeyValuePatternStart)
	offsetValue := strconv.Itoa(pe.OffsetValueStart)
	floatStringLen := strconv.Itoa(pe.ValueLength)
	dotIdx := strconv.Itoa(pe.DotPosition)
	keyValueStartPattern := pe.KeyValueStartPattern

	HSStr := pe.HandshakeSecret

	SHTSInnerHashStr := pe.HkdfSHTSInnerHash
	kfsInnerHashStr := pe.HkdfKFSInnerHash
	sfInnerHashStr := pe.HkdfSFInnerHash

	dHSInnerHashStr := pe.HkdfDHSInnerHash
	MSHSInnerHashStr := pe.HkdfMSInnerHash
	SATSInnerHashStr := pe.HkdfSATSInnerHash
	CATSInnerHashStr := pe.HkdfCATSInnerHash
	kSAPPKeyInnerHashStr := pe.HkdfKSAPPKeyInnerHash
	kSAPPIVInnerHashStr := pe.HkdfKSAPPIVInnerHash
	kCAPPKeyInnerHashStr := pe.HkdfKCAPPKeyInnerHash
	kCAPPIVInnerHashStr := pe.HkdfKCAPPIVInnerHash
	plaintextStr := pe.PlaintextToProof
	SFStr := pe.HkdfSF
	SeqCounterStr := pe.Seq
	ciphertextStr := pe.CiphertextToProof

	// threshold := pJson.Threshold // scaled
	threshold := pe.Threshold
	compareMaxLen := strconv.Itoa(pe.CompareMaxBitLen)

	// command to build .arth .in files
	runCmd := exec.Command("java", "-cp", "bin", "examples.generators.transpiled."+p.GeneratorFileName, blockNr, startBlockIdx, keyValuePairLen, offsetKeyValuePair, offsetValue, floatStringLen, dotIdx, keyValueStartPattern, HSStr, SHTSInnerHashStr, kfsInnerHashStr, sfInnerHashStr, dHSInnerHashStr, MSHSInnerHashStr, SATSInnerHashStr, CATSInnerHashStr, kSAPPKeyInnerHashStr, kSAPPIVInnerHashStr, kCAPPKeyInnerHashStr, kCAPPIVInnerHashStr, plaintextStr, SFStr, SeqCounterStr, ciphertextStr, threshold, compareMaxLen)
	// log.Println("cmd:::", runCmd)
	runCmd.Dir = p.Config.JSnarkBuildPath

	// build circuit
	data, err := runCmd.Output()
	if err != nil {
		log.Println("runCmd.Output error:", err)
		return err
	}
	log.Println(string(data))

	return nil
}

func (p *Prover) GenerateProof() error {
	// TODO: fix hardcoded path
	// ZK snark setup and proof generation
	setupCmd := exec.Command(p.Config.LibSnarkBuildPath+"jsnark_interface/run_generate_prove",
		p.Config.JSnarkBuildPath+p.GeneratorFileName+"_Circuit.arith", p.Config.JSnarkBuildPath+p.GeneratorFileName+"_Circuit.in")
	setupCmd.Dir = "./"

	// compute setup and proof
	data, err := setupCmd.Output()
	if err != nil {
		log.Println("setupCmd.Output() error:", err, data)
		return err
	}

	// print output
	log.Println(string(data))

	//TODO: replace with API call
	// copy proof files
	copyCmd := exec.Command("mv", "-f", "proof.raw", p.Config.LibSnarkBuildPath)
	copyCmd.Dir = "./"
	err = copyCmd.Run()

	copyCmd = exec.Command("mv", "-f", "vk.raw", p.Config.LibSnarkBuildPath)
	err = copyCmd.Run()

	return nil
}

package main

import (
	p "client/policy"
	pp "client/postprocess"
	prv "client/prove"
	r "client/request"
	u "client/utils"
	"time"

	"flag"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {

	// logging settings
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// checks logging flag if program is called as ./main.go -debug
	debug := flag.Bool("debug", false, "sets log level to debug.")

	// Measurement flag
	measure := flag.Bool("measure", false, "enable measurement logs")

	// checks for -server flag
	server := flag.String("server", "local", "server to connect to.")

	// checks for -request flag
	request := flag.Bool("request", false, "send request to server.")

	// checks for handshake only -hsonly flag
	hsonly := flag.Bool("hsonly", false, "establishes tcp tls session with server and returns.")

	// setup should be called at trusted proxy verifier
	// check for -setup flag
	setup := flag.Bool("setup", false, "compiles zk circuit and computes+stores the setup parameters.")

	// check for -prove flag
	prove := flag.Bool("prove", false, "comptes zk proof for policy.")

	// check for -stats flag
	stats := flag.Bool("stats", false, "measures file sizes of zk and transcript files.")

	// Session ID for measurements
	sessionID := flag.String("sessionid", "", "session ID for the client.")

	// Set Server parameters
	serverDomain := flag.String("serverdomain", "", "URL of the proxy server")
	serverEndpoint := flag.String("serverendpoint", "", "URL of the proxy server")

	// Set Proxy URL's
	proxyListenerURL := flag.String("proxylistener", "", "URL of the proxy server")
	proxyServerURL := flag.String("proxyserver", "", "URL of the proxy server")

	flag.Parse()

	if *proxyServerURL == "" {
		log.Error().Msg("proxyServerURL not set. Please provide the -proxyserver flag.")
		return
	}

	// Set the default log level to Disabled
	zerolog.SetGlobalLevel(zerolog.Disabled)

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debugging activated.")
	} else if *measure {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Trace().Msg("Debugging activated.")
	}

	// Measurement initialization
	measurements := u.NewMeasurements(*sessionID)

	if *request {

		if *proxyListenerURL == "" {
			log.Error().Msg("proxyListenerURL not set. Please provide the -proxylistener flag.")
			return
		}

		measurements.Start("PostProcess")

		if *server == "local" {
			handleRequest(*hsonly, *serverDomain, *serverEndpoint, *proxyListenerURL)
		}

		if *server == "paypal" {
			measurements.Start("SendRequest")
			handlePaypalRequest(*hsonly, *serverDomain, *serverEndpoint, *proxyListenerURL)
			measurements.End("SendRequest")
		}

		measurements.Start("ProcessKDC")
		handlePostProcessKDC()
		measurements.End("ProcessKDC")
		measurements.Start("PostProcessRecord")
		handlePostProcessRecord(*server)
		measurements.End("PostProcessRecord")

		// Prepare data to be sent
		kdcShared, err := u.ReadAndCheckFile("local_storage/kdc_shared.json")
		if err != nil {
			log.Error().Err(err)
			return
		}

		recordTagPublic, err := u.ReadAndCheckFile("local_storage/recordtag_public_input.json")
		if err != nil {
			log.Error().Err(err)
			return
		}

		recordDataPublic, err := u.ReadAndCheckFile("local_storage/recorddata_public_input.json")
		if err != nil {
			log.Error().Err(err)
			return
		}

		kdcPublicInput, err := u.ReadAndCheckFile("local_storage/kdc_public_input.json")
		if err != nil {
			log.Error().Err(err)
			return
		}

		combinedData := &u.CombinedData{
			KDCShared:        kdcShared,
			RecordTagPublic:  recordTagPublic,
			RecordDataPublic: recordDataPublic,
			KDCPublicInput:   kdcPublicInput,
		}

		measurements.Start("SendCombinedDataToProxy")
		err = u.SendCombinedDataToProxy("postprocess", *proxyServerURL, combinedData)
		measurements.End("SendCombinedDataToProxy")

		if err != nil {
			log.Error().Err(err).Msg("Failed to complete postprocess on proxy.")
			return
		}

		measurements.End("PostProcess")

		// Check and create /performance directory if it doesn't exist
		if err := u.CheckAndCreateDir("performance"); err != nil {
			log.Error().Err(err).Msg("Failed to create performance directory.")
			return
		}

		// Dump the measurements to a CSV file in /performance directory
		err = measurements.DumpToCSV("performance/measurements_client.csv")
		if err != nil {
			log.Error().Err(err).Msg("Failed to write measurements to CSV.")
			return
		}
	}

	if *prove {
		log.Debug().Msgf("Server value: %+v", *server)

		measurements.Start("CompleteProve")

		policy, err := p.New(p.ServerPolicyPaths[*server])
		if err != nil {
			log.Error().Msg("Read policy file")
		}

		log.Debug().Msgf("Loaded policy: %+v", policy)

		// MEASURE - Start time assign circuit
		measurements.Start("CircuitAssign")

		// get witness
		_, assignment, err := prv.CircuitAssign(policy.ThresholdValue)
		if err != nil {
			log.Error().Msg("prv.ComputeWitness()")
		}

		measurements.End("CircuitAssign")

		// compute proof
		backend := "groth16"

		measurements.Start("ComputeProof")
		err = prv.ComputeProof(backend, assignment, measurements)
		if err != nil {
			log.Error().Msg("prv.ComputeProof()")
		}
		measurements.End("ComputeProof")

		proofFilePath := "local_storage/circuits/oracle_" + backend + ".proof" // Modify this to the correct path
		success, err := u.SendProofToProxy("/verify", *proxyServerURL, proofFilePath)

		if !success {
			log.Error().Err(err).Msg("Failed to complete verification on proxy.")
			return
		}

		measurements.End("CompleteProve")

		// Check and create /performance directory if it doesn't exist
		if err = u.CheckAndCreateDir("performance"); err != nil {
			log.Error().Err(err).Msg("Failed to create performance directory.")
			return
		}

		// Dump the measurements to a CSV file in /performance directory
		err = measurements.DumpToCSV("performance/measurements_client.csv")
		if err != nil {
			log.Error().Err(err).Msg("Failed to write measurements to CSV.")
			return
		}

	}

	// call setup
	if *setup {

		policy, err := p.New(p.ServerPolicyPaths[*server])
		if err != nil {
			log.Error().Msg("Read policy file")
		}

		circuit, _, err := prv.CircuitAssign(policy.ThresholdValue)
		if err != nil {
			log.Error().Msg("prv.ComputeWitness()")
		}

		backend := "groth16"
		ccs, err := prv.CompileCircuit(backend, circuit)
		if err != nil {
			log.Error().Msg("prv.CompileCircuit()")
		}

		// computes the setup parameters
		err = prv.ComputeSetup(backend, ccs)
		if err != nil {
			log.Error().Msg("prv.ComputeSetup()")
		}
	}

	// print statistics data
	if *stats {

		err := u.ZkStats()
		if err != nil {
			log.Error().Msg("u.ZkStats()")
		}
	}
}

func handlePaypalRequest(hsonly bool, serverDomain string, serverEndpoint string, proxyListenerURL string) {

	config := &r.PaypalConfig{
		ReferenceID: "testReferenceID2",
		AmountValue: "38002.2",
		ReturnURL:   "https://example.com/return",
		CancelURL:   "https://example.com/cancel",
	}

	requestTLS := r.NewRequestPayPal(serverDomain, serverEndpoint, proxyListenerURL, config)

	// TODO - Replace the bearer token with the one you get from PayPal.
	requestTLS.AccessToken = "Bearer A21AAId3zDgiyoOjT3AoE5EOOipq_WX5Hpfs7S9YE_eJCUk5fB91uH4mnPlaJcNy_Jrq9RLdMUm3bxoHUO_p_3OTou2-uDQcA"
	realPaypalRequestID := "7b92603e-77ed-4896-8e78-5dea2050476b"

	data, err := requestTLS.PostToPaypal(true, realPaypalRequestID)
	if err != nil {
		log.Error().Err(err).Msg("Failed to post to PayPal.")
		return
	}
	if !hsonly {
		err = requestTLS.Store(data)
		if err != nil {
			log.Error().Msg("req.Store(data)")
		}
	}
}

func handleRequest(hsonly bool, serverDomain string, serverEndpoint string, proxyListenerURL string) {
	req := r.NewRequest(serverDomain, serverEndpoint, proxyListenerURL)
	data, err := req.Call(hsonly)
	if err != nil {
		log.Error().Msg("req.Call()")
	}
	if !hsonly {
		err = req.Store(data)
		if err != nil {
			log.Error().Msg("req.Store(data)")
		}
	}
}

func handlePostProcessKDC() {

	// read in session data
	toBshared, err := pp.Read()
	if err != nil {
		log.Error().Msg("pp.Compute()")
	}

	// // derive public data necessary to verify SF and server certificate
	// err = pp.ProcessSF(toBshared)
	// if err != nil {
	// 	log.Error().Msg("pp.ProcessSF(toBshared)")
	// }

	// derive public data necessary to derive the server application traffic key and iv
	sdataMap, err := pp.DeriveKeyIvSATS(toBshared)
	if err != nil {
		log.Error().Msg("pp.DeriveKeyIvSATS(toBshared)")
	}

	// derive public data necessary to derive the client application traffic key and iv
	cdataMap, err := pp.DeriveKeyIvCATS(toBshared)
	if err != nil {
		log.Error().Msg("pp.DeriveKeyIvCATS(toBshared)")
	}

	// computes shared values necessary to confirm public input params
	err = pp.KdcShared(toBshared, sdataMap, cdataMap)
	if err != nil {
		log.Error().Msg("pp.KdcShared")
	}

	// only public input for kdc circuit
	err = pp.KdcPublicInput(sdataMap, cdataMap)
	if err != nil {
		log.Error().Msg("pp.KdcPublicInput")
	}

	err = pp.KdcPrivateInput(sdataMap)
	if err != nil {
		log.Error().Msg("pp.KdcPrivateInput")
	}
}

func handlePostProcessRecord(server string) {

	start := time.Now() // Add this line

	// authentication tag
	/////////////////////
	recordPerSequence, err := pp.ReadServerRecords()
	if err != nil {
		log.Error().Msg("pp.ReadServerRecords")
	}

	// prints record data
	// pp.ShowPlaintext(recordPerSequence)

	sParams, err := pp.ReadServerParams()
	if err != nil {
		log.Error().Msg("pp.ReadServerRecords")
	}

	// generates recordtag_public_input.json
	// no private input stored because private input (iv, key) must be derived in circuit
	// important: sequence number used as public input to compute on right record
	pp.RecordTagZkInput(sParams, recordPerSequence)

	// policy based public input extraction for record layer data
	// stores parameters in recorddata_public_input.json
	err = pp.ParsePlaintextWithPolicy(server, recordPerSequence)
	if err != nil {
		log.Error().Msg("pp.ParsePlaintextWithPolicy")
	}

	elapsed := time.Since(start)
	log.Debug().Str("elapsed", elapsed.String()).Msg("postprocess_record time.")
}

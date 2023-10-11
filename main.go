package main

import (
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


	if *request {
		
		if *proxyListenerURL == "" {
			log.Error().Msg("proxyListenerURL not set. Please provide the -proxylistener flag.")
			return
		}

		startTime := time.Now()

		handleRequest(*hsonly, *serverDomain, *serverEndpoint, *proxyListenerURL)
		handlePostProcessKDC()
		handlePostProcessRecord()

		// Prepare data to be sent
		kdcShared, err := u.ReadJSONFile("local_storage/kdc_shared.json")
		if err != nil {
			log.Error().Err(err).Msg("Failed to read kdc_shared.json")
			return
		}
		recordTagPublic, err := u.ReadJSONFile("local_storage/recordtag_public_input.json")
		if err != nil {
			log.Error().Err(err).Msg("Failed to read recordtag_public_input.json")
			return
		}
		recordDataPublic, err := u.ReadJSONFile("local_storage/recorddata_public_input.json")
		if err != nil {
			log.Error().Err(err).Msg("Failed to read recorddata_public_input.json")
			return
		}
		kdcPublicInput, err := u.ReadJSONFile("local_storage/kdc_public_input.json")
		if err != nil {
			log.Error().Err(err).Msg("Failed to read kdc_public_input.json")
			return
		}

		combinedData := &u.CombinedData{
			KDCShared:        kdcShared,
			RecordTagPublic:  recordTagPublic,
			RecordDataPublic: recordDataPublic,
			KDCPublicInput:   kdcPublicInput,
		}

		err = u.SendCombinedDataToProxy("postprocess", *proxyServerURL, combinedData)

		if err != nil {
			log.Error().Err(err).Msg("Failed to complete postprocess on proxy.")
			return
		}

		endTimePostProcess := time.Now()

		// 3) Calculate the duration
		durationPostProcess := endTimePostProcess.Sub(startTime)

		// 4) Log the duration
		log.Info().Str("duration", durationPostProcess.String()).Msg("Total time taken from the start of the request, sending /postprocess to proxy & receiving a response from proxy.")	
	}

	if *prove {
		
		startTime := time.Now()

		// get witness
		_, assignment, err := prv.CircuitAssign()
		if err != nil {
			log.Error().Msg("prv.ComputeWitness()")
		}

		// compute proof
		backend := "groth16"
		err = prv.ComputeProof(backend, assignment)
		if err != nil {
			log.Error().Msg("prv.ComputeProof()")
		}

		proofFilePath := "local_storage/circuits/oracle_" + backend + ".proof" // Modify this to the correct path
		success, err := u.SendProofToProxy("/verify", *proxyServerURL, proofFilePath)

		if !success {
			log.Error().Err(err).Msg("Failed to complete verification on proxy.")
			return
		}

		endTimeProve := time.Now()

		// 3) Calculate the duration
		durationProve := endTimeProve.Sub(startTime)

		// 4) Log the duration
		log.Info().Str("duration", durationProve.String()).Msg("Total time taken to create the proof, sending /verify to proxy & receiving a response from proxy.")	

	}
	

	// call setup
	if *setup {

		circuit, _, err := prv.CircuitAssign()
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
    start := time.Now()

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

	elapsed := time.Since(start)
    log.Debug().Str("elapsed", elapsed.String()).Msg("postprocess_kdc time.")
}

func handlePostProcessRecord() {

	start := time.Now()  // Add this line

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
	err = pp.ParsePlaintextWithPolicy(recordPerSequence)
	if err != nil {
		log.Error().Msg("pp.ParsePlaintextWithPolicy")
	}

    elapsed := time.Since(start)
    log.Debug().Str("elapsed", elapsed.String()).Msg("postprocess_record time.")
}

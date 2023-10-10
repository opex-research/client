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

	// checks for -request flag
	request := flag.Bool("request", false, "send request to server.")

	// checks for handshake only -hsonly flag
	hsonly := flag.Bool("hsonly", false, "establishes tcp tls session with server and returns.")

	// checks for -postprocess-kdc flag
	postprocess_kdc := flag.Bool("postprocess-kdc", false, "prepares data for zk circuit.")

	// checks for -postprocess-record flag
	postprocess_record := flag.Bool("postprocess-record", false, "prepares record layer data for zk circuit proofs.")

	// setup should be called at trusted proxy verifier
	// // check for -setup flag
	// setup := flag.Bool("setup", false, "compiles zk circuit and computes+stores the setup parameters.")

	// check for -prove flag
	prove := flag.Bool("prove", false, "comptes zk proof for policy.")

	// check for -stats flag
	stats := flag.Bool("stats", false, "measures file sizes of zk and transcript files.")

	flag.Parse()

	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// activated check
	log.Debug().Msg("Debugging activated.")

	// call request package
	if *request {
		// optionally change to r.NewRequest(configs) for better config handling
		req := r.NewRequest()
		data, err := req.Call(*hsonly)
		if err != nil {
			log.Error().Msg("req.Call()")
		}
		if !*hsonly {
			err = req.Store(data)
			if err != nil {
				log.Error().Msg("req.Store(data)")
			}
		}
	}

	// call postprocess package
	if *postprocess_kdc {

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

	if *postprocess_record {

		start := time.Now()

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

	// // call setup
	// if *setup {

	// 	circuit, _, err := prv.CircuitAssign()
	// 	if err != nil {
	// 		log.Error().Msg("prv.ComputeWitness()")
	// 	}

	// 	backend := "groth16"
	// 	ccs, err := prv.CompileCircuit(backend, circuit)
	// 	if err != nil {
	// 		log.Error().Msg("prv.CompileCircuit()")
	// 	}

	// 	// computes the setup parameters
	// 	err = prv.ComputeSetup(backend, ccs)
	// 	if err != nil {
	// 		log.Error().Msg("prv.ComputeSetup()")
	// 	}
	// }

	// call prove package
	if *prove {

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
	}

	// print statistics data
	if *stats {

		err := u.ZkStats()
		if err != nil {
			log.Error().Msg("u.ZkStats()")
		}
	}
}

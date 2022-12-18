package commands

import (
	"errors"
	"fmt"
	"log"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	pcred "github.com/anonymoussubmission001/origo/dependencies/credentials"
	pc "github.com/anonymoussubmission001/origo/prover"
)

func ProverRequestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prover-request",
		Short: "http client API request with policy and credentials.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// check input argumetns, at least 2
			if len(args) < 2 {
				// start cmd output with empty line
				fmt.Println()
				err := errors.New("\n  please provide policy and credential filenames without extension: origo prover-request <policy-filename> <credential-filename>\n")
				return err
			}
			policyFileName := args[0]
			credentialFileName := args[1]

			// start logger
			f2, start, err := StartLogging("prover-request")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			// initialize client
			client, err := pc.NewClient(policyFileName, credentialFileName)
			if err != nil {
				log.Println("pc.NewClient() error:", err)
				return err
			}

			// perform request
			err = client.RequestAPI()
			if err != nil {
				log.Println("client.RequestAPI() error:", err)
				return err
			}

			// logs
			fmt.Println("***: prover has successfully performed an API request.")

			logrus.SetOutput(f2)

			// stop logger
			err = StopLogging("prover-request", f2, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			return nil

		},
	}

	return cmd
}

func ProverCompileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prover-compile",
		Short: "compile snark circuit and tls handshake and record data into arithmetic representation for zkp backend. please make sure to transpile policy and collect tls handshake and record data for the same policy first.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// check input argumetns, at least 2
			if len(args) < 2 {
				// start cmd output with empty line
				fmt.Println()
				err := errors.New("\n  please provide generator and policy filename without extension: origo prover-compile <generator-filename> <policy-filename>\n")
				return err
			}
			generatorFileName := args[0]
			policyFileName := args[1]

			// start logger
			f, start, err := StartLogging("prover-compile")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			// perform checks
			// - policy has been transpiled
			// - data for the respective proof has been collected

			prover, err := pc.NewProver(policyFileName, generatorFileName, false)
			if err != nil {
				log.Println("pc.NewProver() error:", err)
				return err
			}

			// perform request
			err = prover.CompileCircuit()
			if err != nil {
				log.Println("prover.CompileCircuit() error:", err)
				return err
			}

			// logs
			fmt.Println("***: prover has successfully compiled snark circuit and data to arithmetic representation.")

			// stop logger
			err = StopLogging("prover-compile", f, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			return nil
		},
	}

	return cmd
}

func ProverProveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prover-prove",
		Short: "parses data and generates policy-compliant proof. please make sure to transpile policy and collect tls data and record for policy first.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// check input argumetns, at least 1
			if len(args) < 1 {
				// start cmd output with empty line
				fmt.Println()
				err := errors.New("\n  please provide generator filename without extension: origo prover-prove <generator-filename>\n")
				return err
			}
			//policyFileName := args[0]
			generatorFileName := args[0]

			// perform checks
			// - policy has been transpiled
			// - data for the respective proof has been collected

			// start logger
			f, start, err := StartLogging("prover-prove")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			prover, err := pc.NewProver("", generatorFileName, true)
			if err != nil {
				log.Println("pc.NewProver() error:", err)
				return err
			}

			// perform request
			err = prover.GenerateProof()
			if err != nil {
				log.Println("prover.GenerateProof() error:", err)
				return err
			}

			// logs
			fmt.Println("***: prover has successfully generated cpolicy-compliant proof.")

			// stop logger
			err = StopLogging("prover-prove", f, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			return nil
		},
	}

	return cmd
}

func ProverCredsRefreshCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prover-credentials-refresh",
		Short: "refreshes the credential configuration of the specified filename.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// check for credential filename as input argument
			if len(args) < 1 {
				fmt.Println()
				return errors.New("\n  please provide credential filename without extension: origo prover-credentials-refresh <credential-filename>\n")
			}
			credName := args[0]

			// start logger
			f, start, err := StartLogging("prover-credentials-refresh")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			// client
			cc, err := pcred.NewCredsClient(credName)
			if err != nil {
				log.Println("pcred.NewCredsClient() error:", err)
				return err
			}

			// refresh token
			err = cc.RequestToken()
			if err != nil {
				log.Println("cc.RequestToken() error:", err)
				return err
			}

			// create new order and set order ID as URL private part
			err = cc.SetOrder()
			if err != nil {
				log.Println("cc.SetOrder() error:", err)
				return err
			}

			// this order can then be fetched and proven in ZKP by our protocol
			fmt.Println("***: prover has successfully refreshed credentials.")

			// stop logger
			err = StopLogging("prover-credentials-refresh", f, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			return nil
		},
	}

	return cmd
}

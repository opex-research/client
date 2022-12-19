package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"

	lp "github.com/anonymoussubmission001/origo/dependencies/ledger_policy"
	tp "github.com/anonymoussubmission001/origo/transpiler"
)

func PolicyTranspileCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy-transpile",
		Short: "transpiles policy and constraints into snark circuit.",
		RunE: func(cmd *cobra.Command, args []string) error {

			// check for config name as input argument
			if len(args) < 2 {
				fmt.Println()
				err := errors.New("\n  please provide policy filename and generator filename without file extensions: origo policy-transpile <policy-filename> <generator-filename>\n")
				return err
			}
			policyName := args[0]
			generatorFileName := args[1]

			// start logger
			f, start, err := StartLogging("policy-transpile")
			if err != nil {
				log.Println("StartLogging error", err)
				return err
			}

			// TODO: fix hardcoded path
			// read config file
			jsonFile, err := os.Open("dependencies/ledger_policy/" + policyName + ".json")
			if err != nil {
				log.Println("os.Open() error", err)
				return err
			}
			defer jsonFile.Close()

			// parse json
			byteValue, _ := ioutil.ReadAll(jsonFile)
			var policyJson lp.Policy
			json.Unmarshal(byteValue, &policyJson)

			// check configs
			// fmt.Println("config values:", policyJson)

			// check if enough constraints in policy
			if len(policyJson.Constraints) < 1 {
				//log.Println("error: not enough constraints in selected policy.")
				err := errors.New("Not enough constraints in selected policy.")
				return err
			}

			// run transpiler
			t := tp.NewTranspiler(generatorFileName, policyJson.Constraints[0].Constraint)
			err = t.Transpile()
			if err != nil {
				log.Println("t.transpile error:", err)
				return err
			}

			// stop logger
			err = StopLogging("policy-transpile", f, start)
			if err != nil {
				log.Println("StopLogging error", err)
				return err
			}

			return nil
		},
	}

	return cmd
}

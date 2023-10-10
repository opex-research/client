package prove

import (
	u "client/utils"

	"github.com/rs/zerolog/log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"

	// "github.com/consensys/gnark/backend/plonkfri"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

func CompileCircuit(backend string, circuit frontend.Circuit) (constraint.ConstraintSystem, error) {

	// init builders
	var builder frontend.NewBuilder
	// var srs kzg.SRS
	switch backend {
	case "groth16":
		builder = r1cs.NewBuilder
	case "plonk":
		builder = scs.NewBuilder
	case "plonkFRI":
		builder = scs.NewBuilder
	}

	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
	if err != nil {
		log.Error().Msg("frontend.Compile")
		return nil, err
	}

	// serialize constraint system
	u.Serialize(ccs, "./local_storage/circuits/oracle_"+backend+".ccs")
	// checkSum(ccs, "CCS")

	return ccs, nil
}

func ComputeSetup(backend string, ccs constraint.ConstraintSystem) error {

	// kzg setup if using plonk
	var srs kzg.SRS
	if backend == "plonk" {
		srs, err := test.NewKZGSRS(ccs)
		if err != nil {
			log.Error().Msg("test.NewKZGSRS(ccs)")
			return err
		}
		u.Serialize(srs, "./local_storage/circuits/oracle_"+backend+".srs")
	}

	// proof system execution
	switch backend {
	case "groth16":

		// setup
		pk, vk, err := groth16.Setup(ccs)
		if err != nil {
			log.Error().Msg("groth16.Setup")
			return err
		}
		u.Serialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		u.Serialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")

	case "plonk":

		// setup
		pk, vk, err := plonk.Setup(ccs, srs)
		if err != nil {
			log.Error().Msg("plonk.Setup")
			return err
		}
		u.Serialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		u.Serialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")

	case "plonkFRI":

		// setup
		// pk, vk, err := plonkfri.Setup(ccs)
		// if err != nil {
		// 	log.Error().Msg("plonkfri.Setup")
		// 	return err
		// }
		// u.Serialize(pk, "./local_storage/circuits/oracle_"+backend+".pk")
		// u.Serialize(vk, "./local_storage/circuits/oracle_"+backend+".vk")
	}
	return nil
}

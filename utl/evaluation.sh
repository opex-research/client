#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd ${SCRIPT_DIR}

cd ${SCRIPT_DIR}/..

###### function declarations ############

cleanEvaluationLogs()
{
  # echo "I was called as : $@"
  echo "cleaning evaluation logs"
  rm -rf log
}

cleanCapturedTraffic()
{
  echo "cleaning capture traffic data"
  rm -rf local_storage
}

cleanSnarkFiles()
{
  echo "cleaning snark specific files"
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/src/examples/generators/transpiled/LocalGen.java
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/bin/examples/generators/transpiled/LocalGen.class

  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/LocalGen_Circuit.arith
  rm -rf dependencies/jsnark-demo/JsnarkCircuitBuilder/LocalGen_Circuit.in
}

runEvaluationLocal()
{
  ###### protocol evaluation  ############

  echo "start evaluation"

  # logging cleanup
  cleanEvaluationLogs
  mkdir log

  ###### local mode ######################

  # define policies to evaluate
  policyList="policy_local1 policy_local2"

  # start servers

  # Iterate the string variable using for loop
  for val in $policyList; do

    # cleaning files
    cleanCapturedTraffic
    mkdir local_storage

    # clean up snark files
    cleanSnarkFiles

    # print policy name
    echo evaluate policy file: $val

    # run protocol
    ./origo policy-transpile $val LocalGen
    ./origo prover-request $val local1

    ./origo prover-compile LocalGen $val
    ./origo prover-prove LocalGen
  done

  echo "evaluation done"
}

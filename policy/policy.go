package policy

import (
	"encoding/json"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

type Policy struct {
	Substring            string `json:"substring"`
	ValueStartIdxAfterSS int    `json:"value_start_idx_after_ss"`
	ValueLength          int    `json:"value_length"`
	ThresholdValue       string `json:"threshold_value"`
	ValueConstraint      string `json:"value_constraint"`
}

func New() (Policy, error) {
	// open file
	file, err := os.Open("policy/policy.json")
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return Policy{}, err
	}
	defer file.Close()
	// read in data
	data, err := io.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("io.ReadAll(file)")
		return Policy{}, err
	}
	// parse json into policy struct
	var policy Policy
	err = json.Unmarshal(data, &policy)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return Policy{}, err
	}
	return policy, nil
}

package prover

type ProverConfig struct {
	JSnarkBuildPath           string
	LibSnarkBuildPath         string
	StoragePath               string
	ProveSentRecordsFileName  string
	ServerSentRecordsFileName string
	PathCaCrt                 string
	PathProverPem             string
	PathProverKey             string
	PolicyPath                string
	Rebuild                   bool
}

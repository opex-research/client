setupDeveloperHost:
	./setup-developer-host-common.sh

clean:
	. ./evaluation.sh && cleanEvaluationLogs
	. ./evaluation.sh && cleanCapturedTraffic
	. ./evaluation.sh && cleanSnarkFiles

build:
	./build.sh

buildDockerImage:
	./buildDockerImage.sh

buildDockerImageClean:
	sudo docker image rm "origo-prover:latest" || true
	$(MAKE) -C . buildDockerImage

runDockerImage:
	sudo docker container rm "origo-prover" || true
	sudo docker run --name "origo-prover" -it "origo-prover:latest"

runEvaluationLocal:
	. ./evaluation.sh && runEvaluationLocal

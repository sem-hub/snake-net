FLAGS=-ldflags "-s -w"
build:
	cd cmd/snake-net && go build ${FLAGS} -o snake-net
	cd cmd/benchmarks && go build ${FLAGS} -o benchmarks
windows:
	cd cmd/snake-net && GOOS=windows GOARCH=amd64 go build ${FLAGS} -o snake-net.exe
linux-arm64:
	cd cmd/snake-net && GOOS=linux GOARCH=arm64 go build ${FLAGS} -o snake-net

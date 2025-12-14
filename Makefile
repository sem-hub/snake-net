FLAGS=-ldflags "-s -w"
build:
	cd cmd/snake-net && go build ${FLAGS} -o snake-net
	cd cmd/benchmarks && go build ${FLAGS} -o benchmarks
windows:
	cd cmd/snake-net && GOOS=windows GOARCH=amd64 go build ${FLAGS} -o snake-net.exe
	cd cmd/benchmarks && GOOS=windows GOARCH=amd64 go build ${FLAGS} -o benchmarks.exe
linux-arm64:
	cd cmd/snake-net && CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build ${FLAGS} -o snake-net
	cd cmd/benchmarks && CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build ${FLAGS} -o benchmarks
clean:
	rm -f cmd/snake-net/snake-net
	rm -f cmd/benchmarks/benchmarks

FLAGS=-ldflags "-s -w"
BENCHMARKTAGS="-tags=hmac_sha256,hmac_blake2b,poly1305"
ALLTAGS=-tags=$(shell grep -r '//go:build'|grep -v 'setup'|grep -v '|' |awk '{print $$2}'| tr '\n' ','|sed 's/.$$//')

ifeq (,$(MAKECMDGOALS))
MAKECMDGOALS=build
endif
ifeq ($(filter %-compact,$(MAKECMDGOALS)),$(MAKECMDGOALS))
ALLTAGS=
TARGET=$(MAKECMDGOALS:-compact=)
$(MAKECMDGOALS): $(TARGET)
endif

build:
	cd cmd/snake-net && go build ${FLAGS} ${ALLTAGS} -o snake-net
	cd cmd/benchmarks && go build ${FLAGS} ${BENCHMARKTAGS} -o benchmarks
	@ls -la cmd/snake-net/snake-net
windows:
	cd cmd/snake-net && GOOS=windows GOARCH=amd64 go build ${FLAGS} ${ALLTAGS} -o snake-net.exe
	cd cmd/benchmarks && GOOS=windows GOARCH=amd64 go build ${FLAGS} ${BENCHMARKTAGS} -o benchmarks.exe
linux-arm64:
	cd cmd/snake-net && CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build ${FLAGS} ${ALLTAGS} -o snake-net
	cd cmd/benchmarks && CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc GOOS=linux GOARCH=arm64 go build ${FLAGS} ${BENCHMARKTAGS} -o benchmarks
clean:
	rm -f cmd/snake-net/snake-net
	rm -f cmd/benchmarks/benchmarks

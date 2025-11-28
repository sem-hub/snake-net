FLAGS=-ldflags "-s -w"
build:
	cd cmd && go build ${FLAGS} -o snake-net
windows:
	cd cmd && GOOS=windows GOARCH=amd64 go build ${FLAGS} -o snake-net.exe
linux-arm64:
	cd cmd && GOOS=linux GOARCH=arm64 go build ${FLAGS} -o snake-net

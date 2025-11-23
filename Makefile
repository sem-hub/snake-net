FLAGS=-ldflags "-s -w"
build:
	cd cmd && go build ${FLAGS} -o snake-net
windows:
	cd cmd && GOOS=windows GOARCH=amd64 go build ${FLAGS} -o snake-net.exe

VERSION=`git describe --tags`
BUILD=`date +%FT%T%z`
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.build=${BUILD}"

build: 
	CGO_ENABLED=1 go build ${LDFLAGS} -o bin/dnscap-tool

build-all: build-linux build-darwin build-windows

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/dnscap-tool-linux-amd64

build-darwin:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o bin/dnscap-tool-darwin-amd64

build-windows:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o bin/dnscap-tool-windows-amd64.exe

clean:
	rm -rf bin/dnscap-tool
	rm -rf bin/dnscap-tool-linux-amd64
	rm -rf bin/dnscap-tool-darwin-amd64
	rm -rf bin/dnscap-tool-windows-amd64.exe
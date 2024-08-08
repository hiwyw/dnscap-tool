VERSION=`git describe --tags`
BUILD=`date +%FT%T%z`
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.build=${BUILD}"

build: 
	CGO_ENABLED=1 go build ${LDFLAGS} -o bin/dnscap-tool

clean:
	rm -rf bin/dnscap-tool
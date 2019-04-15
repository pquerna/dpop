
GOPATH := $(shell go env GOPATH)
APPPATH := ${GOPATH}/bin/demo-dpop
CODESIGN_IDENTITY := "Developer ID Application: ScaleFT Inc (HV2G9Z3RP5)"

# We must compile with -ldflags="-s" to omit
# DWARF info on OSX when compiling with the
# 1.5 toolchain. Otherwise the resulting binary
# will be malformed once we codesign it and
# unable to execute.
# See https://github.com/golang/go/issues/11887#issuecomment-126117692.
GOFLAGS := -ldflags="-s"

all: test build

build-signed:
	rm -f ${APPPATH}
	go install ${GOFLAGS} ./cmds/demo-dpop
	security find-certificate -c ${CODESIGN_IDENTITY}
	./cmds/demo-dpop/build-app.sh ${APPPATH} ${CODESIGN_IDENTITY}
	spctl --raw --assess --ignore-cache --no-cache "dist/DemoDpop.app"

build:
	go install ${GOFLAGS} ./cmds/demo-dpop

test:
	go test -v ./. ./enclave

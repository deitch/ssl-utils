BIN := ca
LOCALBIN := ./$(BIN)
INSTALLBIN := ${GOPATH}/bin/$(BIN)

.PHONY: build clean fmt test fmt-check

export GO111MODULE=on

GOFILES := $(shell find . -name '*.go')
build: $(LOCALBIN)
$(LOCALBIN):
	go build -o $@ .

install: $(INSTALLBIN)
$(INSTALLBIN):
	go build -o $@

clean:
	@rm -f $(BIN)

fmt:
	gofmt -w -s $(GOFILES)

fmt-check:
	@FMTOUT=$$(gofmt -l $(GOFILES)); \
	if [ -n "$${FMTOUT}" ]; then echo $${FMTOUT}; exit 1; fi

vet:
	go vet ./...

test:
	go test ./...


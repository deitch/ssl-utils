BIN := ca
GOBIN ?= $(shell go env GOPATH)/bin
LOCALBIN := ./$(BIN)
INSTALLBIN := $(GOBIN)/$(BIN)

.PHONY: build clean fmt test fmt-check lint golint golangci-lint

export GO111MODULE=on

LINTER ?= $(GOBIN)/golangci-lint
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

golangci-lint: $(LINTER)
$(LINTER):
	go get github.com/golangci/golangci-lint/cmd/golangci-lint@v1.17.1

golint:
ifeq (, $(shell which golint))
	go get -u golang.org/x/lint/golint
endif

## Lint the files
lint: golint golangci-lint
	@$(LINTER) run --disable-all --enable=golint ./...

test:
	go test ./...


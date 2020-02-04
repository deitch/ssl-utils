BIN := ca
LOCALBIN := ./$(BIN)
INSTALLBIN := ${GOPATH}/bin/$(BIN)

.PHONY: build clean fmt

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

vet:
	go vet ./...

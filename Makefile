# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
# and for my OS
ARCH ?= $(BUILDARCH)
OS ?= $(BUILDOS)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif

BINDIR := ./dist
BIN := ca
GOBINDIR ?= $(shell go env GOPATH)/bin
LOCALBIN := $(BINDIR)/$(BIN)-$(OS)-$(ARCH)
INSTALLBIN := $(GOBINDIR)/$(BIN)

.PHONY: build clean fmt test fmt-check lint golint golangci-lint

export GO111MODULE=on

LINTER ?= $(GOBINDIR)/golangci-lint
LINTER_VERSION ?= v1.23.3
GOFILES := $(shell find . -name '*.go')

$(BINDIR):
	mkdir -p $@

build: $(LOCALBIN) $(BIN)
$(LOCALBIN): $(BINDIR)
	GOOS=$(OS) GOARCH=$(ARCH) go build -o $@ .
$(BIN):
	if [ "$(OS)" = "$(BUILDOS)" -a "$(ARCH)" = "$(BUILDARCH)" ]; then ln -s $(LOCALBIN) $@; fi

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
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBINDIR) $(LINTER_VERSION)

golint:
ifeq (, $(shell which golint))
	go get -u golang.org/x/lint/golint
endif

## Lint the files
lint: golint golangci-lint
	@$(LINTER) run --disable-all --enable=golint ./...

test:
	go test ./...


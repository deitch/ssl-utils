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
LINTER_VERSION ?= v1.46.2
GOFILES := $(shell find . -name '*.go')

$(BINDIR):
	mkdir -p $@

build: $(LOCALBIN) $(BIN)
$(LOCALBIN): $(BINDIR)
	CGO_ENABLED=0 GOOS=$(OS) GOARCH=$(ARCH) go build -o $@ .
$(BIN):
	@if [ "$(OS)" = "$(BUILDOS)" -a "$(ARCH)" = "$(BUILDARCH)" ]; then rm -f $@; ln -s $(LOCALBIN) $@; fi
	@echo $@ linked to binary $(LOCALBIN)

install: $(INSTALLBIN)
$(INSTALLBIN):
	CGO_ENABLED=0 go build -o $@

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

revive:
ifeq (, $(shell which revive))
	go install github.com/mgechev/revive@latest
endif

## Lint the files
lint: revive golangci-lint
	@$(LINTER) run --enable=revive ./...

test:
	go test ./...


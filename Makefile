# Quality gates and builds for conductor-files. GOWORK=off: the module is
# checked on its own.
export GOWORK := off
GOBIN := $(shell go env GOPATH)/bin
STATICCHECK := $(GOBIN)/staticcheck
GOVULNCHECK := $(GOBIN)/govulncheck
VERSION ?= $(shell git describe --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test check fmt vet staticcheck vulncheck tools lab-test

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/conductor-files ./cmd/conductor-files

test:
	go test -race ./...

check: fmt vet staticcheck vulncheck test

fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags lab ./internal/labtest/

staticcheck: tools
	$(STATICCHECK) ./...
	$(STATICCHECK) -tags lab ./internal/labtest/

vulncheck: tools
	$(GOVULNCHECK) ./...

# Integration tests on fs1 in the main lab (server-home): scripts/lab-test.sh.
lab-test:
	./scripts/lab-test.sh

tools:
	@test -x $(STATICCHECK) || go install honnef.co/go/tools/cmd/staticcheck@latest
	@test -x $(GOVULNCHECK) || go install golang.org/x/vuln/cmd/govulncheck@latest

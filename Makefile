GO ?= go
PYTHON ?= python3

.PHONY: build test lint fmt check cross-build model-check telemetry-check demo
build:
	mkdir -p bin
	$(GO) build -o bin/controller ./apps/controller
	$(GO) build -o bin/endpoint-agent ./apps/endpoint-agent
test:
	$(GO) test -race ./...
lint:
	$(GO) vet ./...
fmt:
	$(GO) fmt ./...
check: lint test model-check
	test -z "$$($(GO) fmt ./...)"
cross-build:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 $(GO) build -o bin/endpoint-agent-windows.exe ./apps/endpoint-agent
	GOOS=darwin GOARCH=arm64 $(GO) build -o bin/endpoint-agent-darwin ./apps/endpoint-agent
model-check:
	PYTHONPATH=models/src $(PYTHON) -m unittest discover -s models/tests
telemetry-check:
	$(PYTHON) -m unittest discover -s models/tests -p 'test_telemetry_schema.py'
demo: build
	$(PYTHON) tools/demo.py

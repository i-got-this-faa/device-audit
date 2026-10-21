GO ?= go
PYTHON ?= python3

.PHONY: build test lint fmt check cross-build model-check telemetry-check contract-check replay-check demo tailcat-lab-check tailcat-lab-proof
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
contract-check:
	$(PYTHON) tools/contract_conformance.py --go "$(GO)"
replay-check: build
	$(GO) build -o bin/endpoint-replay ./tools/fakes/endpoint-replay
	$(GO) test -race -count=1 ./tools/fakes/...
	$(PYTHON) tools/replay_smoke.py
demo: build
	$(PYTHON) tools/demo.py
# The experimental dependency graph stays outside the application module.
tailcat-lab-check:
	cd networking/tailcat-lab && $(GO) vet ./...
	cd networking/tailcat-lab && $(GO) test -race -count=1 -timeout=150s ./...
	cd networking/tailcat-lab && $(GO) mod verify
	cd networking/tailcat-lab && test -z "$$($(GO) fmt ./...)"
tailcat-lab-proof:
	GO=$(GO) networking/tailcat-lab/run-proof.sh

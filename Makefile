.PHONY: test build vet
test:
	go test ./...
vet:
	go vet ./...
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o opentprm ./cmd/opentprm
sbom:
	go version -m ./opentprm || true

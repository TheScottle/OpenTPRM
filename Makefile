.PHONY: test build vet sbom gosec provenance-stub cosign-verify docker-buildx-note
test:
	go test ./...
vet:
	go vet ./...
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o opentprm ./cmd/opentprm
sbom: build
	@mkdir -p dist
	go run github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.9.0 app -json -output dist/opentprm.cdx.json -main cmd/opentprm .
	@echo "wrote dist/opentprm.cdx.json"
gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.22.10 -quiet -fmt text ./...
provenance-stub:
	@chmod +x scripts/provenance-stub.sh
	./scripts/provenance-stub.sh
cosign-verify:
	@chmod +x scripts/cosign-verify.sh
	./scripts/cosign-verify.sh $(TARGET)
docker-buildx-note:
	@echo "Multi-arch (handbook): docker buildx build --platform linux/amd64,linux/arm64 -t opentprm:local -f deploy/Dockerfile ."

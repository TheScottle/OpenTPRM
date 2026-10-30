# syntax=docker/dockerfile:1
ARG GO_IMAGE=golang:1.27-bookworm
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS="-trimpath" GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG GOFIPS140=off
RUN GOFIPS140=${GOFIPS140} go build -buildvcs=true \
    -ldflags="-s -w -buildid= -X main.version=${VERSION}" \
    -o /out/opentprm ./cmd/opentprm

FROM ${RUNTIME_IMAGE}
COPY --from=build /out/opentprm /usr/local/bin/opentprm
USER 65532:65532
EXPOSE 8443 9443
HEALTHCHECK CMD ["/usr/local/bin/opentprm", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/opentprm"]
CMD ["serve", "--config", "/etc/opentprm/config.yaml"]

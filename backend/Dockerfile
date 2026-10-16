FROM golang:1.27.2-bookworm AS build
WORKDIR /src
ENV GOMAXPROCS=2 GOFLAGS=-p=2 GODEBUG=http2client=0
COPY go.mod go.sum ./
RUN --mount=type=cache,id=cherrysecurity-go-modules,target=/go/pkg/mod go mod download && go mod verify
COPY . .
RUN test ! -e /src/browser-fixture.json && test ! -e /src/.env
RUN --mount=type=cache,id=cherrysecurity-go-modules,target=/go/pkg/mod --mount=type=cache,id=cherrysecurity-go-build,target=/root/.cache/go-build CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/admin ./cmd/admin && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/simulator ./cmd/simulator
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/ /app/
USER 65532:65532
ENTRYPOINT ["/app/server"]

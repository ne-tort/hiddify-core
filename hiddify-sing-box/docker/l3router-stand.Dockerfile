# sing-box fork image for l3router stand (experiments/router/stand/l3router).
# Build: from this repo root (hiddify-sing-box)
#   docker compose -f ../stand/l3router/docker-compose.l3router-static-clients.yml build
#
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY . .
ENV CGO_ENABLED=0
RUN GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -tags with_gvisor,with_clash_api,with_utls,with_l3router \
    -o /out/sing-box ./cmd/sing-box

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["/usr/local/bin/sing-box"]

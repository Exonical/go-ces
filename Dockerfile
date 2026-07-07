FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /go-ces-server ./cmd/go-ces-server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /go-ces-server /usr/local/bin/go-ces-server
EXPOSE 8443
ENTRYPOINT ["go-ces-server"]

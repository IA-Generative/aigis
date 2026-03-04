FROM golang:1.25-alpine AS base

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY device/go.mod device/go.sum ./
RUN go mod download


FROM base AS dev

COPY device/go.mod device/go.sum ./
RUN go mod download
RUN go install github.com/air-verse/air@latest

COPY device/ /app/
COPY ./migrations ./migrations

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]


FROM base AS builder

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /device-service ./cmd/server


FROM scratch AS prod

COPY --from=builder /device-service /device-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

ENTRYPOINT ["/device-service"]
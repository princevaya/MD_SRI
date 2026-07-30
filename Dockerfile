# Stage 1: Build Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy application source code
COPY . .

# Build statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o mdsri cmd/main.go

# Stage 2: Clean final runtime image
FROM alpine:3.19

WORKDIR /app

# Add certificates
RUN apk add --no-cache ca-certificates

# Copy compiled binary and required static assets
COPY --from=builder /app/mdsri /app/mdsri
COPY --from=builder /app/configs /app/configs
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/reports /app/reports

# Setup output folders
RUN mkdir -p /app/output && chmod 777 /app/output

EXPOSE 8080

ENTRYPOINT ["/app/mdsri"]
CMD ["server", "--port", "8080", "--config", "configs/config.yaml"]

# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for dependency fetching
RUN apk add --no-cache git ca-certificates

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o guardrail ./cmd/guardrail

# Final stage
FROM alpine:3.22

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Create non-root user
RUN addgroup -g 1001 guardrail && \
    adduser -D -u 1001 -G guardrail guardrail

# Copy the binary from builder stage
COPY --from=builder /app/guardrail .

# Copy configuration files
COPY --from=builder /app/configs /etc/guardrail/

# Create necessary directories
RUN mkdir -p /app/data && \
    chown -R guardrail:guardrail /app

# Switch to non-root user
USER guardrail

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ./guardrail --version || exit 1

# Set the entrypoint
ENTRYPOINT ["./guardrail"]

# Default command
CMD ["--help"]
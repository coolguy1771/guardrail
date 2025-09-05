# Build stage
FROM golang:1.25-alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS builder

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

# Ensure configs directory exists for copying
RUN mkdir -p /app/configs || true

# Final stage
FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Create non-root user
RUN addgroup -g 1001 guardrail && \
  adduser -D -u 1001 -G guardrail guardrail

# Copy the binary from builder stage
COPY --from=builder /app/guardrail .

# Copy configuration files
COPY --from=builder /app/configs/ /etc/guardrail/

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
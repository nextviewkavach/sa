# Build Stage
FROM golang:1.23-alpine AS builder

# Install git and others if needed
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum separately to cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app statically
RUN go build -ldflags="-s -w" -o app .

# ----------------------------------------------------------

# Final Stage (Minimal image)
FROM alpine:latest

# Install SSL certificates (for HTTPS and email support)
RUN apk add --no-cache ca-certificates

# Set working directory
WORKDIR /app

# Copy built binary from builder
COPY --from=builder /app/app .

# Expose port
EXPOSE 8080

# Run the app
CMD ["./app"]

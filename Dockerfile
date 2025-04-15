# syntax=docker/dockerfile:1

# Base image
FROM golang:1.21-alpine

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source files
COPY . .

# Build the Go app
RUN go build -o app .

# Expose port (Railway sets env var PORT)
EXPOSE 8000

# Start the app
CMD ["./app"]

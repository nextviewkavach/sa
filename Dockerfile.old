# Start from Alpine base
FROM alpine:latest

# Install required packages and Go manually
RUN apk add --no-cache curl git bash build-base && \
    curl -LO https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go

# Set Go environment
ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH=/go
WORKDIR /app

# Copy Go module files first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go binary
RUN go build -o app .

# Expose the port from your Go app
EXPOSE 8080

# Run the app
CMD ["./app"]

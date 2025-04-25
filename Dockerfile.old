# Start from a base Alpine image
FROM alpine:latest

# Install curl, git, and build tools
RUN apk add --no-cache curl git bash build-base

# Install Go 1.23 manually
RUN curl -LO https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    go version

# Set environment variables
ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH=/go
WORKDIR /app

# Copy files
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build your Go app
RUN go build -o app .

EXPOSE 8080

CMD ["./app"]

# Use latest Go image with toolchain support
FROM golang:1.22

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Enable automatic toolchain download
ENV GOTOOLCHAIN=auto

# Download dependencies
RUN go mod download

# Copy the rest of your code
COPY . .

# Build your Go app
RUN go build -o app .

# Expose the port Railway expects
EXPOSE 8000

# Run the app
CMD ["./app"]

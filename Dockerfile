# Build Stage
FROM golang:1.24.2-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -ldflags="-s -w" -o app .

# ----------------------------------------------------------

# Final Stage
FROM alpine:latest

# Install SSL certs and timezone data
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/app .

# Set timezone env (optional, good practice)
ENV TZ=Asia/Kolkata

EXPOSE 8080

CMD ["./app"]

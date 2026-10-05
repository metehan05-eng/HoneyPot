# Stage 1: Build
FROM golang:1.22-alpine AS builder
RUN apk --no-cache add gcc musl-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o sentinel-trap ./cmd/honeypot

# Stage 2: Final Minimal Image
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/sentinel-trap .
COPY --from=builder /app/configs ./configs
EXPOSE 2222 8080 8081 21 23 3306 6379
CMD ["./sentinel-trap"]
FROM golang:1.25.6-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-s -w" -o main ./cmd/api
FROM scratch

COPY --from=builder /app/main /main

EXPOSE 8080
ENTRYPOINT ["/main"]
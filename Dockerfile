FROM node:24-alpine AS web-builder
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
COPY internal/webui/ /src/internal/webui/
RUN npm run build

FROM golang:1.24-alpine AS go-builder
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=web-builder /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/openppp2-management ./cmd/management

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S openppp2 \
    && adduser -S -G openppp2 openppp2 \
    && mkdir -p /app/data \
    && chown -R openppp2:openppp2 /app
WORKDIR /app
COPY --from=go-builder /out/openppp2-management /usr/local/bin/openppp2-management
USER openppp2
EXPOSE 8080
VOLUME ["/app/data"]
ENTRYPOINT ["openppp2-management"]

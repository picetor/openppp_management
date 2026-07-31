FROM node:24-alpine AS web-builder
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
COPY internal/webui/ /src/internal/webui/
# 限制 Node 堆内存上限，避免小内存服务器上 vite/esbuild 构建时 OOM
ENV NODE_OPTIONS=--max-old-space-size=1024
RUN npm run build

FROM golang:1.24-alpine AS go-builder
WORKDIR /src
# 构建并行度：go build 默认按 GOMAXPROCS 全核并行，这里限制为 2，
# 避免服务器内存不足时 OOM。可用 --build-arg GO_BUILD_PARALLEL=4 调整。
ARG GO_BUILD_PARALLEL=2
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
COPY --from=web-builder /src/internal/webui/dist ./internal/webui/dist
RUN CGO_ENABLED=0 go build -p ${GO_BUILD_PARALLEL} -trimpath -ldflags="-s -w" -o /out/openppp2-management ./cmd/management

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

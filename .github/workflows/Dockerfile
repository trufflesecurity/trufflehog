# ══════════════════════════════════════════════════════════
# 🐳 Multi-Stage Optimized Dockerfile
# ══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════
# Stage 1: Build Stage
# ═══════════════════════════════════════════════════════
FROM golang:1.21-alpine AS builder

# تثبيت الأدوات المطلوبة
RUN apk add --no-cache \
    git \
    make \
    ca-certificates \
    tzdata

WORKDIR /app

# نسخ ملفات Go modules أولاً (للاستفادة من الكاش)
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# نسخ باقي الكود
COPY . .

# بناء التطبيق
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -a -installsuffix cgo \
    -o /app/bin/app \
    ./cmd/main.go

# ═══════════════════════════════════════════════════════
# Stage 2: Runtime Stage (Distroless)
# ═══════════════════════════════════════════════════════
FROM gcr.io/distroless/static-debian12:nonroot

# إضافة metadata
LABEL maintainer="your-email@example.com" \
      description="Your Application Description" \
      version="1.0.0"

# نسخ الملفات الضرورية من builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# نسخ التطبيق
COPY --from=builder /app/bin/app /app

# استخدام مستخدم غير root
USER nonroot:nonroot

# تحديد المنفذ
EXPOSE 8080

# نقطة الدخول
ENTRYPOINT ["/app"]

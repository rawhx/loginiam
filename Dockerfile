# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
FROM golang:1.25.5-alpine AS build

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOTOOLCHAIN=local

# Unduh dependency dulu supaya layer ini di-cache selama go.mod/go.sum tidak
# berubah (BuildKit cache mount mempercepat build ulang).
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# -trimpath: hilangkan path lokal dari binary. -s -w: strip symbol & DWARF
# supaya binary lebih kecil. Hasilnya static (CGO_ENABLED=0).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# ---- Runtime stage ---------------------------------------------------------
# distroless static: ~2 MB, sudah ada CA certs untuk HTTPS ke brone.ub.ac.id,
# tanpa shell/package manager = permukaan serangan minimal.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/api /api

USER nonroot:nonroot
ENV ADDR=:8080
EXPOSE 8080

ENTRYPOINT ["/api"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/api", "healthcheck"]


# loginiam API

API sederhana untuk login SSO UB (Brone/IAM UB) berbasis Go. Mendukung login awal, verifikasi OTP/2FA, batch login, monitoring (Prometheus), structured logging (JSON), dan rate limiting.

## Daftar Endpoint

| Method | Path | Deskripsi |
|---|---|---|
| GET | `/health` | Health check sederhana. |
| GET | `/livez` | Liveness check (proses hidup). |
| GET | `/readyz` | Readiness check (siap menerima trafik). |
| GET | `/metrics` | Metrics Prometheus (http_requests_total, http_request_duration_seconds, login_attempts_total, otp_verifications_total, upstream_errors_total, http_rate_limited_total). |
| POST | `/login` | Login awal dengan username & password. Bisa langsung sukses (mengembalikan student) atau butuh OTP (mengembalikan otp_required + flow + devices). |
| POST | `/otp/verify` | Verifikasi kode OTP untuk melanjutkan login. Mengembalikan student jika sukses. |
| POST | `/batch` | Login banyak kredensial sekaligus (terbatas concurrency). |

## Environment Variables

| Var | Default | Deskripsi |
|---|---|---|
| `ADDR` | `:8080` | Alamat & port server (format `:8080` atau `127.0.0.1:8080`). |
| `VERBOSE` | `true` | Logging detail internal (SIAM). Set `false` untuk produksi. |
| `TRUST_PROXY` | `false` | Jika `true`, `X-Forwarded-For` digunakan untuk key rate limiter. Hanya aktifkan jika ada reverse proxy terpercaya. |
| `LOGIN_BURST` | `30` | Burst token bucket untuk `/login`. |
| `LOGIN_RATE_PER_SEC` | `0.5` | Rate token bucket per detik untuk `/login`. |
| `OTP_BURST` | `20` | Burst untuk `/otp/verify`. |
| `OTP_RATE_PER_SEC` | `0.33` | Rate per detik untuk `/otp/verify`. |
| `BATCH_BURST` | `5` | Burst untuk `/batch`. |
| `BATCH_RATE_PER_SEC` | `0.05` | Rate per detik untuk `/batch`. |

## Authentication (Basic Auth untuk /metrics)

Hanya endpoint **`/metrics`** yang diproteksi Basic Auth (privat). Endpoint lain (`/login`, `/otp/verify`, `/batch`, `/health`, `/livez`, `/readyz`) bersifat **publik**.

Variabel env:
| Var | Default | Deskripsi |
|---|---|---|
| `METRICS_AUTH_ENABLED` | `true` | Proteksi Basic Auth untuk `/metrics` (`true`/`false`). |
| `AUTH_USER` | - | Username (wajib jika `METRICS_AUTH_ENABLED=true`). |
| `AUTH_PASS` | - | Password (wajib jika `METRICS_AUTH_ENABLED=true`). |
| `AUTH_REALM` | `loginiam` | Realm untuk WWW-Authenticate. |

Catatan keamanan:
- Jika `METRICS_AUTH_ENABLED=true` tapi `AUTH_USER`/`AUTH_PASS` kosong, `/metrics` merespons `500 AUTH_NOT_CONFIGURED` (fail-closed) sehingga tidak terbuka.
- Set `METRICS_AUTH_ENABLED=false` hanya jika `/metrics` memang boleh diakses publik (mis. di balik jaringan internal).

Contoh penggunaan:
```bash
# /metrics butuh Basic Auth
curl -u admin:password http://127.0.0.1:8080/metrics

# Endpoint lain publik
curl http://127.0.0.1:8080/health
```


## Request & Response

### POST `/login`
```json
{
  "username": "nim",
  "password": "password"
}
```

Response (sukses langsung):
```json
{
  "student": {
    "nim": "...",
    "nama": "...",
    "email": "...",
    "fakultas": "...",
    "prodi": "..."
  }
}
```

Response (butuh OTP):
```json
{
  "otp_required": true,
  "flow": "<flow-id>",
  "devices": [
    { "value": "device-id", "name": "Google Authenticator", "checked": true }
  ]
}
```

Response (gagal):
```json
{ "error": true, "code": "AUTH_FAILED", "message": "Username atau password salah." }
```

### POST `/otp/verify`
```json
{
  "flow": "<flow-id>",
  "otp": "123456",
  "credential_id": "optional"
}
```

Response (sukses):
```json
{
  "student": { "nim": "...", "nama": "...", "email": "...", "fakultas": "...", "prodi": "..." }
}
```

Response (kode salah, bisa coba lagi dengan flow baru):
```json
{
  "error": true,
  "status": "invalid_otp",
  "code": "OTP_INVALID",
  "message": "Kode OTP salah. Silakan coba lagi.",
  "otp_required": true,
  "flow": "<flow-baru>",
  "devices": [...]
}
```

Response (flow kedaluwarsa):
```json
{ "error": true, "status": "expired", "code": "OTP_EXPIRED", "message": "Kode OTP kadaluarsa. Silakan login ulang." }
```

### POST `/batch`
```json
{
  "credentials": [
    { "username": "nim1", "password": "pass1" },
    { "username": "nim2", "password": "pass2" }
  ],
  "max_concurrent": 10
}
```

Response:
```json
[
  { "username": "nim1", "result": { "student": {...} }, "err": null },
  { "username": "nim2", "result": null, "err": { "Code": "AUTH_FAILED", "Message": "..." } }
]
```

Keterangan:
- `max_concurrent` opsional. Batas default diterapkan oleh implementasi (<=10 jika <=0).
- Maksimal `500` kredensial per request.
- Body JSON dibatasi `1 MiB`.

## Headers & Rate Limit

- Setiap respons menyertakan `X-Request-ID` (auto-generated jika tidak ada di request).
- Jika melebihi batas rate limit, endpoint mengembalikan `429 Too Many Requests` dengan `Retry-After: 1` dan body error `RATE_LIMITED`.

## Docker

Build & run:
```bash
docker build -t loginiam-api .
docker run -d -p 8080:8080 -e VERBOSE=false loginiam-api
```

Docker Compose:
```bash
docker compose up -d
```

Healthcheck terintegrasi (`/api healthcheck`) dengan interval 30s/timeout 3s/retries 3.

## Catatan Teknis

- OTP store bersifat **in-memory per-proses**. Untuk multi-instance tanpa sticky session, sebaiknya pindah ke Redis (kunci flow 32-byte hex, `GETDEL` + TTL).
- Rate limiter juga **in-memory per-proses**. Untuk pembatasan global lintas instance, pindah ke Redis (token bucket/sliding window).
- Endpoint `/metrics`, `/livez`, `/readyz` sebaiknya dibatasi aksesnya (internal network) jika diekspos ke internet.
- Password **tidak pernah** di-log. Username (NIM) dicatat untuk audit/debugging.

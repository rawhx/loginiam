package main

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenBucket adalah satu ember token per key (mis. per alamat IP).
type tokenBucket struct {
	tokens float64
	last   time.Time
}

// ipLimiter membatasi laju request per key memakai token bucket. Ringan,
// in-memory, tanpa dependency eksternal. Cukup untuk meredam brute-force
// password/OTP maupun banjir request dari satu sumber.
//
// CATATAN: in-memory per-proses. Kalau service multi-instance, tiap instance
// punya hitungan sendiri; untuk pembatasan global lintas instance, pindahkan
// ke Redis (INCR + EXPIRE).
type ipLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*tokenBucket
	capacity float64 // jumlah burst maksimum
	refillPS float64 // token yang ditambahkan per detik (rate)
	idleTTL  time.Duration
	maxKeys  int
	now      func() time.Time
}

func newIPLimiter(capacity, refillPS float64) *ipLimiter {
	if capacity < 1 {
		capacity = 1
	}
	if refillPS <= 0 {
		refillPS = 1
	}
	return &ipLimiter{
		buckets:  make(map[string]*tokenBucket),
		capacity: capacity,
		refillPS: refillPS,
		// Ember dianggap idle kalau butuh waktu jauh lebih lama dari yang
		// diperlukan untuk mengisi ulang penuh, jadi aman dibuang.
		idleTTL: time.Duration(capacity/refillPS*10)*time.Second + time.Minute,
		maxKeys: 100000,
		now:     time.Now,
	}
}

func (l *ipLimiter) allow(key string) bool {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.buckets) > l.maxKeys {
		l.pruneKeysLocked(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: l.capacity, last: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.refillPS
		if b.tokens > l.capacity {
			b.tokens = l.capacity
		}
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// pruneLocked membuang ember yang sudah lama idle. Caller wajib memegang mu.
func (l *ipLimiter) pruneKeysLocked(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.idleTTL {
			delete(l.buckets, k)
		}
	}
}

// clientKey menentukan kunci pembatas. Secara default memakai alamat IP
// koneksi (RemoteAddr). Kalau TRUST_PROXY diaktifkan (service di belakang
// reverse proxy/LB), pakai entri pertama X-Forwarded-For. Jangan aktifkan
// TRUST_PROXY kalau service bisa diakses langsung, karena X-Forwarded-For
// mudah dipalsukan dan bisa dipakai untuk melewati rate limit.
func clientKey(r *http.Request) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// middleware membungkus handler dengan pembatasan laju. Saat kuota habis,
// balas 429 + Retry-After.
func (l *ipLimiter) middleware(path string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientKey(r)) {
			rateLimitedTotal.WithLabelValues(path).Inc()
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Terlalu banyak permintaan. Silakan coba lagi sebentar lagi.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// envFloat membaca env var sebagai float dengan default.
func envFloat(name string, def float64) float64 {
	if v := os.Getenv(name); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

var trustProxy = strings.EqualFold(os.Getenv("TRUST_PROXY"), "true")

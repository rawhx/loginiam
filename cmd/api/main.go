package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"loginiam"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	if v := strings.EqualFold(os.Getenv("VERBOSE"), "false"); v {
		loginiam.Verbose = false
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	initMetrics()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/livez", handleLivez)
	mux.HandleFunc("/readyz", handleReadyz)
	mux.HandleFunc("/metrics", promhttp.Handler().ServeHTTP)
	loginLimiter := newIPLimiter(envFloat("LOGIN_BURST", 30), envFloat("LOGIN_RATE_PER_SEC", 0.5))
	otpLimiter := newIPLimiter(envFloat("OTP_BURST", 20), envFloat("OTP_RATE_PER_SEC", 0.33))
	batchLimiter := newIPLimiter(envFloat("BATCH_BURST", 5), envFloat("BATCH_RATE_PER_SEC", 0.05))

	mux.Handle("/login", loginLimiter.middleware("/login", http.HandlerFunc(handleLogin)))
	mux.Handle("/otp/verify", otpLimiter.middleware("/otp/verify", http.HandlerFunc(handleVerifyOTP)))
	mux.Handle("/batch", batchLimiter.middleware("/batch", http.HandlerFunc(handleBatch)))

	var h http.Handler = mux
	h = authMiddleware(h)
	h = metricsMiddleware(h)
	h = logMiddleware(h)

	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	slog.Info("SIAM login service mendengarkan", "addr", addr)
	if len(os.Args) > 1 && (os.Args[1] == "healthcheck" || os.Args[1] == "--healthcheck") {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			port = "8080"
		}
		healthURL := "http://127.0.0.1:" + port + "/health"
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(healthURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 400 {
				os.Exit(0)
			}
			os.Exit(1)
		}
		// try to see if server is up? maybe another instance? fallback: check if we can bind? no. just exit 1
		os.Exit(1)
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server berhenti", "err", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Handler HTTP
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleLivez(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Body JSON tidak valid: "+err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "username dan password wajib diisi")
		return
	}

	result, err := loginiam.LoginAndGetUser(req.Username, req.Password)
	if err != nil {
		upstreamErrorsTotal.WithLabelValues("login").Inc()
		writeAuthError(w, err)
		return
	}
	if result.OTPRequired {
		loginAttemptsTotal.WithLabelValues("otp_required").Inc()
	} else if result.Student != nil {
		loginAttemptsTotal.WithLabelValues("success").Inc()
	} else if result.Error {
		loginAttemptsTotal.WithLabelValues("failed").Inc()
	} else {
		loginAttemptsTotal.WithLabelValues("other").Inc()
	}
	writeJSON(w, http.StatusOK, result)
}

type verifyOTPRequest struct {
	Flow         string `json:"flow"`
	OTP          string `json:"otp"`
	CredentialID string `json:"credential_id"`
}

func handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var req verifyOTPRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Body JSON tidak valid: "+err.Error())
		return
	}
	req.Flow = strings.TrimSpace(req.Flow)
	if req.Flow == "" || req.OTP == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "flow dan otp wajib diisi")
		return
	}

	result, err := loginiam.VerifyOTP(req.Flow, req.OTP, req.CredentialID)
	if err != nil {
		upstreamErrorsTotal.WithLabelValues("otp_verify").Inc()
		writeAuthError(w, err)
		return
	}
	if result.Student != nil {
		otpVerificationsTotal.WithLabelValues("success").Inc()
	} else if result.Error {
		if result.Status == "invalid_otp" {
			otpVerificationsTotal.WithLabelValues("invalid").Inc()
		} else if result.Status == "expired" {
			otpVerificationsTotal.WithLabelValues("expired").Inc()
		} else {
			otpVerificationsTotal.WithLabelValues("error").Inc()
		}
	} else {
		otpVerificationsTotal.WithLabelValues("other").Inc()
	}
	writeJSON(w, http.StatusOK, result)
}

// ---------------------------------------------------------------------------
// Batch login
// ---------------------------------------------------------------------------

type batchItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type batchRequest struct {
	Credentials   []batchItem `json:"credentials"`
	MaxConcurrent int         `json:"max_concurrent"`
}

func handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	var req batchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Body JSON tidak valid: "+err.Error())
		return
	}
	if len(req.Credentials) == 0 {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "credentials wajib diisi")
		return
	}
	if len(req.Credentials) > maxBatchCreds {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "terlalu banyak credentials (maks "+strconv.Itoa(maxBatchCreds)+")")
		return
	}

	creds := make([]loginiam.Credential, len(req.Credentials))
	for i, item := range req.Credentials {
		creds[i] = loginiam.Credential{Username: strings.TrimSpace(item.Username), Password: item.Password}
	}

	results := loginiam.LoginBatch(creds, req.MaxConcurrent)
	writeJSON(w, http.StatusOK, results)
}

// ---------------------------------------------------------------------------
// Helper respons
// ---------------------------------------------------------------------------

const (
	maxJSONBodyBytes = 1 << 20 // 1 MiB
	maxBatchCreds    = 500
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status", "code"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)
	loginAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Login attempts total",
		},
		[]string{"result"},
	)
	otpVerificationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "otp_verifications_total",
			Help: "OTP verification attempts total",
		},
		[]string{"result"},
	)
	upstreamErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "upstream_errors_total",
			Help: "Upstream errors by stage",
		},
		[]string{"stage"},
	)
	rateLimitedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_rate_limited_total",
			Help: "Requests rejected by the rate limiter",
		},
		[]string{"path"},
	)
)

func initMetrics() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
	prometheus.MustRegister(loginAttemptsTotal)
	prometheus.MustRegister(otpVerificationsTotal)
	prometheus.MustRegister(upstreamErrorsTotal)
	prometheus.MustRegister(rateLimitedTotal)
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		duration := time.Since(start).Seconds()
		statusStr := strconv.Itoa(rec.status)
		httpRequestsTotal.WithLabelValues(r.Method, r.URL.Path, statusStr, "api").Inc()
		httpRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("gagal menulis respons", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]interface{}{
		"error":   true,
		"code":    code,
		"message": message,
	})
}

// writeAuthError memetakan *loginiam.AuthError ke status HTTP yang sesuai
// tanpa membocorkan detail teknis ke client.
func writeAuthError(w http.ResponseWriter, err error) {
	var authErr *loginiam.AuthError
	if errors.As(err, &authErr) {
		status := http.StatusBadGateway
		switch authErr.Code {
		case loginiam.ErrCodeAuthFailed:
			status = http.StatusUnauthorized
		case loginiam.ErrCodeOTPExpired:
			status = http.StatusGone
		case loginiam.ErrCodeInternal:
			status = http.StatusInternalServerError
		}
		writeError(w, status, string(authErr.Code), authErr.Message)
		return
	}

	slog.Error("error tak dikenal", "err", err)
	writeError(w, http.StatusInternalServerError, string(loginiam.ErrCodeInternal), "Terjadi kesalahan sistem.")
}

func decodeJSON(r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Metode tidak diizinkan")
}

// logMiddleware mencatat method, path, status, dan durasi tiap request.
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		duration := time.Since(start)
		id := requestID(r)
		w.Header().Set("X-Request-ID", id)
		slog.Info("request",
			"request_id", id,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"dur", duration.String(),
			"dur_ms", duration.Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return strconv.FormatInt(time.Now().UnixNano(), 16)
}

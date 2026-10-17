package main

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
)

var (
	// metricsAuthEnabled mengontrol proteksi Basic Auth khusus endpoint
	// /metrics. Default aktif (privat). Set METRICS_AUTH_ENABLED=false untuk
	// membukanya (mis. saat pengembangan lokal).
	metricsAuthEnabled = !strings.EqualFold(os.Getenv("METRICS_AUTH_ENABLED"), "false")
	authUser           = os.Getenv("AUTH_USER")
	authPass           = os.Getenv("AUTH_PASS")
	authRealm          = os.Getenv("AUTH_REALM")
)

func init() {
	if authRealm == "" {
		authRealm = "loginiam"
	}
}

// metricsAuthMiddleware melindungi endpoint /metrics dengan Basic Auth.
// Endpoint lain (/login, /otp/verify, /batch, /health, /livez, /readyz)
// dibiarkan publik. Jika METRICS_AUTH_ENABLED=false, /metrics juga publik.
//
// Bila proteksi aktif tetapi AUTH_USER/AUTH_PASS kosong, server menolak
// dengan 500 AUTH_NOT_CONFIGURED (fail-closed) sehingga /metrics tetap privat
// tanpa diam-diam terbuka.
func metricsAuthMiddleware(next http.Handler) http.Handler {
	if !metricsAuthEnabled {
		return next
	}

	if authUser == "" || authPass == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
			writeError(w, http.StatusInternalServerError, "AUTH_NOT_CONFIGURED", "Server auth belum dikonfigurasi (AUTH_USER/AUTH_PASS kosong).")
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Butuh otorisasi (Basic Auth).")
			return
		}

		payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Kredensial tidak valid.")
			return
		}

		cred := string(payload)
		colonIdx := strings.Index(cred, ":")
		if colonIdx < 0 {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Kredensial tidak valid.")
			return
		}

		user := cred[:colonIdx]
		pass := cred[colonIdx+1:]

		if subtle.ConstantTimeCompare([]byte(user), []byte(authUser)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte(authPass)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Kredensial salah.")
	})
}

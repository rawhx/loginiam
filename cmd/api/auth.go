package main

import (
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
)

var (
	authEnabled = strings.EqualFold(os.Getenv("AUTH_ENABLED"), "true")
	authUser    = os.Getenv("AUTH_USER")
	authPass    = os.Getenv("AUTH_PASS")
	authRealm   = os.Getenv("AUTH_REALM")
)

func init() {
	if authRealm == "" {
		authRealm = "loginiam"
	}
}

func isLocalhost(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "127.0.0.1" || host == "::1" {
		return true
	}
	return false
}

// authMiddleware menerapkan Basic Auth jika AUTH_ENABLED=true.
// Endpoint /health dibebaskan untuk request dari localhost (agar Docker
// HEALTHCHECK tetap bisa berjalan tanpa kredensial).
func authMiddleware(next http.Handler) http.Handler {
	if !authEnabled {
		return next
	}

	// Validasi kredensial jika enabled
	if authUser == "" || authPass == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+authRealm+`"`)
			writeError(w, http.StatusInternalServerError, "AUTH_NOT_CONFIGURED", "Server auth belum dikonfigurasi (AUTH_USER/AUTH_PASS kosong).")
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass /health untuk localhost
		if r.URL.Path == "/health" && isLocalhost(r) {
			next.ServeHTTP(w, r)
			return
		}

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

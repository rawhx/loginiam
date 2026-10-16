package loginiam

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/andybalholm/cascadia"
	"golang.org/x/net/publicsuffix"
)

// ---------------------------------------------------------------------------
// Konfigurasi & tuning
// ---------------------------------------------------------------------------

const (
	// Pakai trailing slash: tanpa slash, server membalas 301 ke versi http://
	// (downgrade cleartext) yang justru menggantung/tidak responsif. Dengan
	// slash, server langsung 302 ke Keycloak IAM lewat HTTPS.
	brondeEntryURL = "https://brone.ub.ac.id/my/"

	// httpTimeout: batas waktu PER REQUEST (bukan total retry). Tanpa ini,
	// saat server UB kelebihan beban koneksi bisa menggantung tanpa batas dan
	// goroutine menumpuk di memori.
	httpTimeout = 15 * time.Second

	// maxBodyBytes membatasi ukuran body yang kita baca dari satu respons.
	// Halaman Keycloak normal cuma puluhan KB; batas ini jaga-jaga kalau
	// upstream mengirim respons tidak wajar (error page raksasa, dll).
	maxBodyBytes = 5 << 20 // 5 MiB

	// Jumlah retry & jeda antar-retry, meniru persis angka di referensi
	// Laravel: getSession() pakai retry(3,1500), auth() POST pakai
	// retry(3,1500), verifyOtp() POST pakai retry(2,1500).
	retrySession = 3
	retryAuth    = 3
	retryOTP     = 2
	retryBackoff = 1500 * time.Millisecond
)

// userAgent dibuat menyerupai browser asli. User-Agent default Go
// ("Go-http-client/1.1") lebih mudah dikenali sebagai bot oleh WAF/Keycloak
// bot-protection dan bisa memicu blokir/CAPTCHA saat traffic tinggi.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// Verbose mengaktifkan log detail (dump semua field form, semua form di
// halaman, dll) seperti versi sebelumnya. Matikan di production berbeban
// tinggi (mis. lewat env var) untuk menghemat CPU/log volume; pesan STAGE
// penting (START, OTP_REQUIRED, AUTH_FAILED, DONE) tetap selalu dicatat.
var Verbose = true

// ---------------------------------------------------------------------------
// Transport bersama (connection pooling)
// ---------------------------------------------------------------------------

var sharedTransport = &http.Transport{
	MaxIdleConns:          200,
	MaxIdleConnsPerHost:   50,
	MaxConnsPerHost:       100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ForceAttemptHTTP2:     true,
}

// isSecureSSOHost menentukan host yang WAJIB diakses lewat HTTPS. Dipakai
// CheckRedirect supaya redirect http:// dari server tidak memaksa koneksi
// cleartext (yang terbukti menggantung untuk brone.ub.ac.id).
func isSecureSSOHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	for _, h := range []string{"brone.ub.ac.id", "iam.ub.ac.id"} {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// newHTTPClient membuat client ber-cookiejar sendiri (tiap login = sesi
// Keycloak sendiri, tidak boleh berbagi cookie dengan login lain) tapi tetap
// memakai sharedTransport, supaya koneksi TCP/TLS ke host yang sama dipakai
// ulang lintas login.
func newHTTPClient() (*http.Client, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Jar:       jar,
		Timeout:   httpTimeout,
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("terlalu banyak redirect")
			}
			if req.URL.Scheme == "http" && isSecureSSOHost(req.URL.Host) {
				req.URL.Scheme = "https"
				if req.URL.Port() == "80" {
					req.URL.Host = req.URL.Hostname()
				}
			}
			return nil
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Selector CSS yang dikompilasi sekali (hot-path optimization)
// ---------------------------------------------------------------------------

var (
	selLoginForm  = cascadia.MustCompile("form#kc-form-login, form[action*='authenticate']")
	selSAMLInput  = cascadia.MustCompile("input[name='SAMLResponse']")
	selOTPForm    = cascadia.MustCompile("form#kc-otp-login-form, form#kc-totp-login-form, form[id*='otp'], form[id*='totp']")
	selOTPInput   = cascadia.MustCompile("input[name='otp']")
	selOTPDevices = cascadia.MustCompile("input[type='radio'][name='selectedCredentialId']")
	selErrorMsg   = cascadia.MustCompile("#input-error, .alert-error, .kc-feedback-text")
	selTitle      = cascadia.MustCompile("title")
	selBody       = cascadia.MustCompile("body")
	selAllForms   = cascadia.MustCompile("form")
	selAllInputs  = cascadia.MustCompile("input")
)

// find/findIn adalah wrapper tipis di atas FindMatcher supaya pemanggilnya
// tetap singkat dibanding doc.FindMatcher(selX) berulang-ulang.
func find(doc *goquery.Document, sel goquery.Matcher) *goquery.Selection {
	return doc.FindMatcher(sel)
}
func findIn(s *goquery.Selection, sel goquery.Matcher) *goquery.Selection {
	return s.FindMatcher(sel)
}

// ---------------------------------------------------------------------------
// Tipe data publik
// ---------------------------------------------------------------------------

type StudentDetails struct {
	NIM   string `json:"nim"`
	Nama  string `json:"nama"`
	Email string `json:"email"`
}

// OTPDevice merepresentasikan satu "tile" kredensial OTP/2FA yang ditawarkan
// Keycloak (mis. Google Authenticator, FreeOTP, dll), setara parseOtpDevices()
// di referensi Laravel. Dikirim ke frontend supaya user bisa memilih device.
type OTPDevice struct {
	Value   string `json:"value"`   // selectedCredentialId yang harus dikirim balik
	Name    string `json:"name"`    // nama tampilan, mis. "Google Authenticator"
	Checked bool   `json:"checked"` // true kalau ini default/satu-satunya device
}

// LoginResult adalah kontrak JSON TUNGGAL yang dikembalikan baik oleh
// LoginAndGetUser maupun VerifyOTP, setara array asosiatif yang dikembalikan
// UbauthService::auth()/verifyOtp() di Laravel ('error', 'otp_required',
// 'flow', 'devices', dst). Handler HTTP tinggal json.Marshal(result).
type LoginResult struct {
	Error       bool            `json:"error"`
	Status      string          `json:"status,omitempty"` // "invalid_otp" | "expired" | "error" (setara $e instanceof OtpChallengeExpired di Laravel)
	Code        ErrCode         `json:"code,omitempty"`
	Message     string          `json:"message,omitempty"`
	OTPRequired bool            `json:"otp_required,omitempty"`
	Flow        string          `json:"flow,omitempty"`    // token untuk dipakai di VerifyOTP
	Devices     []OTPDevice     `json:"devices,omitempty"` // daftar device OTP yang bisa dipilih
	Student     *StudentDetails `json:"student,omitempty"`
}

// Struct untuk parsing SAMLResponse XML
type Response struct {
	XMLName   xml.Name  `xml:"Response"`
	Assertion Assertion `xml:"Assertion"`
}
type Assertion struct {
	Subject   Subject     `xml:"Subject"`
	Attribute []Attribute `xml:"AttributeStatement>Attribute"`
}
type Subject struct {
	NameID string `xml:"NameID"`
}
type Attribute struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// ErrCode adalah kode error yang stabil, aman dipakai caller (mis. untuk
// menentukan pesan di UI atau logika retry), tanpa membocorkan detail teknis.
type ErrCode string

const (
	ErrCodeInternal      ErrCode = "INTERNAL_ERROR"       // masalah di sisi kita (parsing, request gagal dibuat, dll)
	ErrCodeUpstream      ErrCode = "UPSTREAM_UNAVAILABLE" // server UB tidak bisa dihubungi / lambat / status aneh walau sudah diretry
	ErrCodeAuthFailed    ErrCode = "AUTH_FAILED"          // kredensial salah / ditolak IAM / pesan error Keycloak lain
	ErrCodeNeedMoreSteps ErrCode = "NEED_ADDITIONAL_STEP" // SAML tidak ditemukan tanpa pesan error jelas (struktur halaman berubah, dll)
	ErrCodeOTPExpired    ErrCode = "OTP_EXPIRED"          // flow OTP sudah lewat TTL atau tidak ditemukan -- setara OtpChallengeExpired
	ErrCodeOTPInvalid    ErrCode = "OTP_INVALID"          // kode OTP yang dikirim user salah
)

// AuthError adalah error yang aman ditampilkan ke user/caller di production.
// Error() HANYA mengembalikan pesan generik -- detail teknis (status code,
// pesan Keycloak asli, cuplikan HTML, dll) hanya masuk ke log lewat logf(),
// tidak pernah ikut terbawa ke response. Setara catch (\Throwable $e) yang
// di Laravel hanya mengembalikan $e->getMessage() generik ke caller.
type AuthError struct {
	Code    ErrCode
	Message string
}

func (e *AuthError) Error() string {
	return e.Message
}

func newAuthError(code ErrCode, message string) *AuthError {
	return &AuthError{Code: code, Message: message}
}

// Pesan generik yang aman ditampilkan ke user. Diletakkan sebagai konstanta
// biar konsisten dan gampang diubah di satu tempat (misal untuk i18n nanti).
const (
	msgInternalError = "Terjadi kesalahan sistem. Silakan coba lagi beberapa saat lagi."
	msgUpstreamDown  = "Layanan login sedang tidak dapat diakses. Silakan coba lagi nanti."
	msgAuthFailed    = "Username atau password salah."
	msgNeedMoreSteps = "Login tidak dapat diselesaikan. Silakan hubungi admin."
	msgOTPExpired    = "Kode OTP kadaluarsa. Silakan login ulang."
	msgOTPNotFound   = "Sesi login tidak ditemukan. Silakan masukkan NIM dan kata sandi kembali."
	msgOTPInvalid    = "Kode OTP salah. Silakan coba lagi."
	msgAccountIncomp = "Akun UB belum lengkap, hubungi admin SIAM."
)

// logf menambahkan prefix konsisten supaya gampang di-grep di log server.
// username disertakan (password TIDAK PERNAH di-log) supaya kalau ada laporan
// "user X gak bisa masuk", tinggal grep NIM/username itu di log.
func logf(username, stage, format string, args ...interface{}) {
	log.Printf("[SIAM][user=%s][%s] %s", username, stage, fmt.Sprintf(format, args...))
}

// vlogf sama seperti logf tapi hanya aktif kalau Verbose == true. Dipakai
// untuk dump debug yang mahal (semua field form, semua form di halaman)
// supaya tidak membebani CPU/log saat batch ribuan login.
func vlogf(username, stage, format string, args ...interface{}) {
	if !Verbose {
		return
	}
	logf(username, stage, format, args...)
}

// ---------------------------------------------------------------------------
// OTP challenge store
//
// Keycloak minta kode OTP disubmit dengan cookie session PERSIS SAMA dengan
// yang dipakai saat submit username/password. Supaya login bisa "jeda"
// sambil menunggu kode dari authenticator app user, kita simpan http.Client
// (cookiejar-nya) + detail form OTP di memori, diindeks oleh flow token
// acak, dengan TTL -- setara Session::put('ubauth.otp.'.$flowId, [...]) di
// Laravel, hanya saja di sini disimpan di memori proses, bukan di session
// Laravel (yang bisa di-backend-kan ke Redis dsb).
//
// CATATAN: ini in-memory per-proses. Kalau service dijalankan multi-instance
// di belakang load balancer tanpa sticky session, pindahkan store ini ke
// Redis/memcached (serialize cookie jar sebagai daftar *http.Cookie per host).
// ---------------------------------------------------------------------------

const otpChallengeTTL = 5 * time.Minute

type otpChallenge struct {
	Username  string
	Client    *http.Client
	Action    string
	Fields    url.Values
	Devices   []OTPDevice
	CreatedAt time.Time
}

var (
	otpStoreMu sync.Mutex
	otpStore   = map[string]*otpChallenge{}
)

// generateFlowID membuat token acak 32-byte (hex) sebagai identitas sesi OTP
// yang aman ditebak (dikirim ke client sebagai "flow").
func generateFlowID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// pruneOTPChallengesLocked membuang entri kedaluwarsa. Caller WAJIB sudah
// memegang otpStoreMu. Dipanggil setiap ada penyimpanan baru, jadi store
// tidak membengkak tanpa perlu goroutine background terpisah.
func pruneOTPChallengesLocked() {
	now := time.Now()
	for k, v := range otpStore {
		if now.Sub(v.CreatedAt) > otpChallengeTTL {
			delete(otpStore, k)
		}
	}
}

func storeOTPChallenge(c *otpChallenge) (string, error) {
	otpStoreMu.Lock()
	defer otpStoreMu.Unlock()

	pruneOTPChallengesLocked()

	flowID, err := generateFlowID()
	if err != nil {
		return "", err
	}
	otpStore[flowID] = c
	return flowID, nil
}

// takeOTPChallenge mengambil DAN menghapus challenge (one-time use): baik
// berhasil maupun salah OTP, flow lama tidak boleh dipakai ulang -- mencegah
// brute-force kode OTP lewat flow token yang sama. Setara resolveOtpChallenge()
// + pengecekan TTL di Laravel (yang melempar OtpChallengeExpired).
func takeOTPChallenge(flowID string) (*otpChallenge, *AuthError) {
	otpStoreMu.Lock()
	defer otpStoreMu.Unlock()

	c, ok := otpStore[flowID]
	if !ok {
		return nil, newAuthError(ErrCodeOTPExpired, msgOTPNotFound)
	}
	delete(otpStore, flowID)

	if time.Since(c.CreatedAt) > otpChallengeTTL {
		return nil, newAuthError(ErrCodeOTPExpired, msgOTPExpired)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// HTTP helper: GET/POST dengan retry+backoff (setara ->retry(n, ms) Laravel)
// ---------------------------------------------------------------------------

// httpResult menampung hasil satu request yang sudah "dihabiskan" (body
// dibaca penuh lalu di-parse jadi goquery.Document), supaya retry bisa
// memutuskan ulang kalau gagal tanpa membocorkan resource (body/koneksi).
type httpResult struct {
	statusCode int
	body       []byte
	doc        *goquery.Document
}

// isRetryableStatus menentukan status HTTP mana yang dianggap transient
// (layak diulang) -- kesalahan sisi server/gateway, bukan kesalahan
// kredensial atau request yang memang salah bentuk.
func isRetryableStatus(code int) bool {
	return code == 0 || code == http.StatusTooManyRequests || code >= 500
}

// doRequestWithRetry mengeksekusi fn (builder *http.Request) sampai
// maxAttempts kali, dengan jeda tetap `backoff` antar percobaan -- meniru
// persis pola ->retry($n, $ms) di referensi Laravel (bukan exponential,
// supaya perilaku timing gampang diprediksi/diuji).
func doRequestWithRetry(client *http.Client, buildReq func() (*http.Request, error), username, stage string, maxAttempts int, backoff time.Duration) (*httpResult, *AuthError) {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := buildReq()
		if err != nil {
			return nil, newAuthError(ErrCodeInternal, msgInternalError)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			vlogf(username, stage, "percobaan %d/%d gagal (network): %v", attempt, maxAttempts, err)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				continue
			}
			logf(username, stage, "semua %d percobaan gagal (network), error terakhir: %v", maxAttempts, lastErr)
			return nil, newAuthError(ErrCodeUpstream, msgUpstreamDown)
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			vlogf(username, stage, "percobaan %d/%d gagal baca body: %v", attempt, maxAttempts, readErr)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				continue
			}
			logf(username, stage, "semua %d percobaan gagal baca body, error terakhir: %v", maxAttempts, lastErr)
			return nil, newAuthError(ErrCodeUpstream, msgUpstreamDown)
		}

		if isRetryableStatus(resp.StatusCode) {
			vlogf(username, stage, "percobaan %d/%d status transient=%d", attempt, maxAttempts, resp.StatusCode)
			if attempt < maxAttempts {
				time.Sleep(backoff)
				continue
			}
			logf(username, stage, "semua %d percobaan status transient, terakhir=%d", maxAttempts, resp.StatusCode)
			return nil, newAuthError(ErrCodeUpstream, msgUpstreamDown)
		}

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
		if err != nil {
			logf(username, stage, "gagal parse HTML: %v", err)
			return nil, newAuthError(ErrCodeInternal, msgInternalError)
		}

		return &httpResult{statusCode: resp.StatusCode, body: body, doc: doc}, nil
	}

	// Tidak tercapai secara normal (loop selalu return), tapi dijaga untuk compiler.
	return nil, newAuthError(ErrCodeUpstream, msgUpstreamDown)
}

func getWithRetry(client *http.Client, reqURL, username, stage string, maxAttempts int, backoff time.Duration) (*httpResult, *AuthError) {
	return doRequestWithRetry(client, func() (*http.Request, error) {
		return http.NewRequest(http.MethodGet, reqURL, nil)
	}, username, stage, maxAttempts, backoff)
}

// postFormWithRetry submit x-www-form-urlencoded ke Keycloak. Header
// `Origin: null` disertakan karena referensi Laravel menandainya "WAJIB"
// (beberapa endpoint IAM UB menolak POST tanpa Origin yang sesuai; `null`
// meniru submit form dari konteks tanpa origin, sama seperti browser pada
// form POST lintas dokumen/file://).
func postFormWithRetry(client *http.Client, action string, data url.Values, username, stage string, maxAttempts int, backoff time.Duration) (*httpResult, *AuthError) {
	encoded := data.Encode()
	return doRequestWithRetry(client, func() (*http.Request, error) {
		req, err := http.NewRequest(http.MethodPost, action, bytes.NewBufferString(encoded))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "null")
		return req, nil
	}, username, stage, maxAttempts, backoff)
}

// ---------------------------------------------------------------------------
// Parsing helper (dipakai di jalur login awal maupun VerifyOTP)
// ---------------------------------------------------------------------------

// hiddenFields mengambil semua <input type="hidden"> dalam sebuah form,
// setara parseHiddenFields() di Laravel.
func hiddenFields(form *goquery.Selection) url.Values {
	values := url.Values{}
	findIn(form, selAllInputs).Each(func(_ int, s *goquery.Selection) {
		typ, _ := s.Attr("type")
		if typ != "hidden" {
			return
		}
		name, ok := s.Attr("name")
		if !ok || name == "" {
			return
		}
		val, _ := s.Attr("value")
		values.Set(name, val)
	})
	return values
}

// parseOTPForm mendeteksi form OTP/2FA Keycloak dan mengekstrak action,
// hidden field, serta daftar device yang bisa dipilih -- setara
// parseOtpForm()/parseOtpDevices() di Laravel.
func parseOTPForm(doc *goquery.Document) *otpChallenge {
	form := find(doc, selOTPForm)
	if form.Length() == 0 {
		return nil
	}
	// Tanpa input `otp`, ini bukan form OTP -- cuma halaman lain yang
	// kebetulan id-nya mengandung kata "otp".
	if findIn(form, selOTPInput).Length() == 0 {
		return nil
	}

	action, _ := form.Attr("action")
	fields := hiddenFields(form)

	var devices []OTPDevice
	findIn(form, selOTPDevices).Each(func(_ int, s *goquery.Selection) {
		val, _ := s.Attr("value")
		_, checked := s.Attr("checked")
		id, _ := s.Attr("id")

		name := "Perangkat"
		if id != "" {
			label := doc.Find(`label[for="` + id + `"]`)
			if t := strings.TrimSpace(label.Find(".pf-c-tile__title").First().Text()); t != "" {
				name = t
			} else if t := strings.TrimSpace(label.Text()); t != "" {
				name = t
			}
		}
		devices = append(devices, OTPDevice{Value: val, Name: name, Checked: checked})
	})

	return &otpChallenge{Action: action, Fields: fields, Devices: devices}
}

// extractKeycloakError membaca pesan error yang ditampilkan Keycloak di
// halaman (salah password, salah OTP, dll) -- setara extractOtpError() dan
// pengecekan `#input-error`/`.alert-error` di Laravel.
func extractKeycloakError(doc *goquery.Document) string {
	return strings.TrimSpace(find(doc, selErrorMsg).First().Text())
}

func hasSAMLResponse(doc *goquery.Document) (string, bool) {
	return find(doc, selSAMLInput).Attr("value")
}

// isKnownCredential memastikan credentialId yang dipilih FRONTEND benar-benar
// salah satu device yang kita tawarkan -- jangan percaya begitu saja nilai
// dari client (sama seperti isKnownCredential() di Laravel).
func isKnownCredential(credentialID string, devices []OTPDevice) bool {
	if credentialID == "" {
		return false
	}
	for _, d := range devices {
		if d.Value == credentialID {
			return true
		}
	}
	return false
}

func defaultCredential(devices []OTPDevice) string {
	for _, d := range devices {
		if d.Checked {
			return d.Value
		}
	}
	if len(devices) > 0 {
		return devices[0].Value
	}
	return ""
}

// parseSAMLToStudent men-decode value atribut SAMLResponse (base64 -> XML)
// dan memetakan atributnya ke StudentDetails -- setara SamlParserService di
// Laravel. Dipakai baik saat login berhasil langsung maupun setelah OTP
// berhasil diverifikasi.
func parseSAMLToStudent(username, samlResp string) (*StudentDetails, *AuthError) {
	vlogf(username, "SAML", "SAMLResponse ditemukan, panjang base64=%d", len(samlResp))

	xmlBytes, err := base64.StdEncoding.DecodeString(samlResp)
	if err != nil {
		logf(username, "SAML", "gagal decode base64: %v", err)
		return nil, newAuthError(ErrCodeInternal, msgInternalError)
	}

	var saml Response
	if err := xml.Unmarshal(xmlBytes, &saml); err != nil {
		logf(username, "SAML", "gagal unmarshal XML SAML: %v. cuplikan xml=%s", err, truncate(string(xmlBytes), 500))
		return nil, newAuthError(ErrCodeInternal, msgInternalError)
	}

	if saml.Assertion.Subject.NameID == "" {
		logf(username, "SAML", "NameID (NIM) kosong di dalam Assertion -- struktur SAML mungkin beda untuk user ini")
	}

	if Verbose {
		attrNames := make([]string, 0, len(saml.Assertion.Attribute))
		for _, attr := range saml.Assertion.Attribute {
			attrNames = append(attrNames, attr.Name)
			vlogf(username, "SAML_ATTR", "attr=%s values=%v", attr.Name, attr.Values)
		}
		vlogf(username, "SAML_ATTR", "daftar semua attribute name dari IdP: %v", attrNames)
	}

	student := &StudentDetails{NIM: saml.Assertion.Subject.NameID}

	for _, attr := range saml.Assertion.Attribute {
		if len(attr.Values) == 0 {
			continue
		}
		value := attr.Values[0]

		switch attr.Name {
		case "fullName", "displayname", "displayName", "nama", "cn":
			if value == "" {
				continue
			}
			if student.Nama == "" || attr.Name == "fullName" {
				student.Nama = value
			}
		case "email":
			if value != "" {
				student.Email = value
			}
		}
	}

	if student.Nama == "" {
		logf(username, "SAML_MAP", "PERINGATAN: Nama tetap kosong setelah mapping -- lihat SAML_ATTR di atas (kalau Verbose aktif)")
	}
	if student.Email == "" {
		logf(username, "SAML_MAP", "PERINGATAN: Email tetap kosong setelah mapping")
	}
	if student.NIM == "" {
		logf(username, "SAML_MAP", "PERINGATAN: NIM (NameID) kosong")
	}

	logf(username, "DONE", "hasil akhir: NIM=%s Nama=%q Email=%q", student.NIM, student.Nama, student.Email)

	return student, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// pageSnapshot mengambil title+cuplikan body, dipakai untuk log diagnostik
// saat hasil halaman tidak dikenali (bukan sukses, bukan OTP, bukan pesan
// error eksplisit).
func pageSnapshot(doc *goquery.Document) (title, snippet string) {
	title = strings.TrimSpace(find(doc, selTitle).First().Text())
	snippet = truncate(strings.TrimSpace(find(doc, selBody).First().Text()), 300)
	return
}

// debugAllForms mencatat SEMUA form di halaman (id + action), bukan cuma
// form login -- jaga-jaga kalau struktur halaman Keycloak berubah. Hanya
// dipanggil saat Verbose aktif karena ini melakukan alokasi string per form.
func debugAllForms(doc *goquery.Document, username, stage string) {
	if !Verbose {
		return
	}
	var forms []string
	find(doc, selAllForms).Each(func(_ int, s *goquery.Selection) {
		id, _ := s.Attr("id")
		act, _ := s.Attr("action")
		forms = append(forms, fmt.Sprintf("id=%q action=%q", id, truncate(act, 80)))
	})
	vlogf(username, stage, "semua form di halaman: %v", forms)
}

// ---------------------------------------------------------------------------
// Step 1: ambil session_code/execution/tab_id dari halaman awal Brone
// (setara getSession() di Laravel), tapi lewat parsing HTML asli (goquery),
// bukan string-slicing manual -- lebih tahan terhadap perubahan kecil pada
// markup, dan actionnya sudah lengkap (session_code+execution+client_id+tab_id)
// jadi tidak perlu disusun ulang manual seperti di referensi Laravel.
// ---------------------------------------------------------------------------

func getLoginFormAction(client *http.Client, username string) (string, *goquery.Selection, *AuthError) {
	res, aerr := getWithRetry(client, brondeEntryURL, username, "GET_SESSION", retrySession, retryBackoff)
	if aerr != nil {
		return "", nil, aerr
	}

	logf(username, "GET_SESSION", "status=%d", res.statusCode)

	form := find(res.doc, selLoginForm)
	if form.Length() == 0 {
		title, snippet := pageSnapshot(res.doc)
		logf(username, "GET_SESSION", "form login tidak ditemukan. title=%q body_snippet=%s", title, snippet)
		return "", nil, newAuthError(ErrCodeUpstream, msgUpstreamDown)
	}

	action, hasAction := form.Attr("action")
	if !hasAction || action == "" {
		logf(username, "GET_SESSION", "form login ditemukan tapi atribut action kosong -- kemungkinan halaman Keycloak berubah struktur")
		return "", nil, newAuthError(ErrCodeUpstream, msgUpstreamDown)
	}

	vlogf(username, "GET_SESSION", "action form login = %s", action)
	return action, form, nil
}

// ---------------------------------------------------------------------------
// Step 2: auth() -- submit username+password ke endpoint authenticate,
// setara UbauthService::auth() di Laravel.
// ---------------------------------------------------------------------------

// LoginAndGetUser menjalankan login SSO UB sampai salah satu dari tiga hasil:
//   - sukses penuh         -> (&LoginResult{Student: ...}, nil)
//   - butuh OTP/2FA        -> (&LoginResult{OTPRequired: true, Flow: ..., Devices: ...}, nil)
//   - gagal (auth/upstream/internal) -> (nil, *AuthError)
//
// Kalau OTPRequired true, lanjutkan dengan VerifyOTP(flow, kodeDariUser, credentialIdPilihanUser).
func LoginAndGetUser(username, password string) (*LoginResult, error) {
	logf(username, "START", "memulai proses login")

	client, err := newHTTPClient()
	if err != nil {
		logf(username, "INIT", "gagal membuat http client: %v", err)
		return nil, newAuthError(ErrCodeInternal, msgInternalError)
	}

	action, loginForm, aerr := getLoginFormAction(client, username)
	if aerr != nil {
		return nil, aerr
	}

	// Data POST: hidden field form (csrf/session token dsb) + username +
	// password + credentialId kosong, setara body yang dikirim auth() di
	// Laravel ('username', 'password', 'credentialId' => '').
	data := hiddenFields(loginForm)
	data.Set("username", username)
	data.Set("password", password)
	data.Set("credentialId", "")

	res, aerr := postFormWithRetry(client, action, data, username, "AUTH", retryAuth, retryBackoff)
	if aerr != nil {
		return nil, aerr
	}
	logf(username, "AUTH", "status=%d", res.statusCode)
	debugAllForms(res.doc, username, "AUTH")

	// Password benar, tidak butuh MFA -> langsung dapat SAMLResponse.
	if samlResp, exists := hasSAMLResponse(res.doc); exists {
		student, serr := parseSAMLToStudent(username, samlResp)
		if serr != nil {
			return nil, serr
		}
		return &LoginResult{Student: student}, nil
	}

	// Password benar, tapi Keycloak minta kode OTP/2FA.
	if otpForm := parseOTPForm(res.doc); otpForm != nil {
		otpForm.Username = username
		otpForm.Client = client
		otpForm.CreatedAt = time.Now()

		flowID, ferr := storeOTPChallenge(otpForm)
		if ferr != nil {
			logf(username, "AUTH", "gagal membuat flow OTP: %v", ferr)
			return nil, newAuthError(ErrCodeInternal, msgInternalError)
		}

		logf(username, "AUTH", "akun ini punya OTP/2FA aktif, flow=%s devices=%d", flowID, len(otpForm.Devices))

		return &LoginResult{
			OTPRequired: true,
			Flow:        flowID,
			Devices:     otpForm.Devices,
		}, nil
	}

	if errMsg := extractKeycloakError(res.doc); errMsg != "" {
		logf(username, "AUTH", "Keycloak menampilkan pesan error: %q", errMsg)
		return nil, newAuthError(ErrCodeAuthFailed, msgAuthFailed)
	}

	title, snippet := pageSnapshot(res.doc)
	logf(username, "AUTH", "SAMLResponse tidak ditemukan dan tidak ada pesan error eksplisit. title=%q body_snippet=%s", title, snippet)
	return nil, newAuthError(ErrCodeNeedMoreSteps, msgNeedMoreSteps)
}

// ---------------------------------------------------------------------------
// Step 3: verifyOtp() -- submit kode OTP ke form hasil scraping step 2,
// setara UbauthService::verifyOtp() di Laravel.
// ---------------------------------------------------------------------------

// VerifyOTP melanjutkan login yang sedang menunggu kode OTP (flow dari
// LoginResult.Flow yang didapat dari LoginAndGetUser). credentialID boleh
// dikosongkan kalau cuma ada satu device terdaftar; kalau diisi tapi tidak
// valid, fallback ke device default/checked -- sama seperti Laravel.
//
// Hasil yang mungkin:
//   - sukses             -> (&LoginResult{Student: ...}, nil)
//   - kode salah         -> (&LoginResult{Error:true, Status:"invalid_otp", OTPRequired:true, Flow:<baru>, Devices:...}, nil)
//   - flow kedaluwarsa   -> (&LoginResult{Error:true, Status:"expired", Code: ErrCodeOTPExpired, Message:...}, nil)
//   - gagal lain         -> (&LoginResult{Error:true, Status:"error", ...}, nil)
func VerifyOTP(flowID, otp, credentialID string) (*LoginResult, error) {
	challenge, aerr := takeOTPChallenge(flowID)
	if aerr != nil {
		// Setara catch (OtpChallengeExpired $e) di Laravel: dikembalikan
		// sebagai LoginResult berstatus "expired", bukan error Go biasa,
		// supaya handler HTTP tetap bisa langsung json.Marshal-kannya.
		return &LoginResult{
			Error:   true,
			Status:  "expired",
			Code:    aerr.Code,
			Message: aerr.Message,
		}, nil
	}
	username := challenge.Username

	logf(username, "OTP_VERIFY", "memverifikasi OTP untuk flow=%s", flowID)

	selected := credentialID
	if !isKnownCredential(selected, challenge.Devices) {
		selected = defaultCredential(challenge.Devices)
	}

	data := url.Values{}
	for k, v := range challenge.Fields {
		data[k] = v
	}
	data.Set("otp", otp)
	data.Set("login", "Sign In")
	if selected != "" {
		data.Set("selectedCredentialId", selected)
	}

	res, postErr := postFormWithRetry(challenge.Client, challenge.Action, data, username, "OTP_VERIFY", retryOTP, retryBackoff)
	if postErr != nil {
		logf(username, "OTP_VERIFY", "flow=%s gagal submit OTP: %v", flowID, postErr.Message)
		return &LoginResult{Error: true, Status: "error", Code: postErr.Code, Message: postErr.Message}, nil
	}

	// Sukses: OTP benar, dapat SAMLResponse.
	if samlResp, exists := hasSAMLResponse(res.doc); exists {
		student, serr := parseSAMLToStudent(username, samlResp)
		if serr != nil {
			return &LoginResult{Error: true, Status: "error", Code: serr.Code, Message: serr.Message}, nil
		}
		logf(username, "OTP_VERIFY", "flow=%s OTP benar, login selesai", flowID)
		return &LoginResult{Student: student}, nil
	}

	// Keycloak menampilkan ulang form OTP -> kode salah. Buat flow BARU
	// (cookie jar yang sama masih valid) supaya user bisa mencoba lagi
	// tanpa login ulang dari awal -- setara startOtpChallenge() dipanggil
	// ulang di cabang invalid_otp pada Laravel.
	if otpForm := parseOTPForm(res.doc); otpForm != nil {
		otpForm.Username = username
		otpForm.Client = challenge.Client
		otpForm.CreatedAt = time.Now()

		newFlowID, ferr := storeOTPChallenge(otpForm)
		if ferr != nil {
			logf(username, "OTP_VERIFY", "flow=%s gagal membuat flow OTP baru: %v", flowID, ferr)
			return &LoginResult{Error: true, Status: "error", Code: ErrCodeInternal, Message: msgInternalError}, nil
		}

		errMsg := extractKeycloakError(res.doc)
		message := msgOTPInvalid
		if errMsg != "" {
			vlogf(username, "OTP_VERIFY", "flow=%s kode OTP salah, flow baru=%s, pesan keycloak=%q", flowID, newFlowID, errMsg)
		}

		return &LoginResult{
			Error:       true,
			Status:      "invalid_otp",
			Code:        ErrCodeOTPInvalid,
			Message:     message,
			OTPRequired: true,
			Flow:        newFlowID,
			Devices:     otpForm.Devices,
		}, nil
	}

	// Bukan sukses, bukan form OTP lagi -> kemungkinan akun belum lengkap
	// setup (setara pengecekan "Account is not fully set up" di Laravel).
	if strings.Contains(string(res.body), "Account is not fully set up") || strings.Contains(string(res.body), "AccountNotFullyConfigured") {
		logf(username, "OTP_VERIFY", "flow=%s akun belum lengkap setup", flowID)
		return &LoginResult{Error: true, Status: "error", Code: ErrCodeNeedMoreSteps, Message: msgAccountIncomp}, nil
	}

	title, snippet := pageSnapshot(res.doc)
	logf(username, "OTP_VERIFY", "flow=%s hasil tidak dikenali. title=%q body_snippet=%s", flowID, title, snippet)

	return &LoginResult{
		Error:   true,
		Status:  "invalid_otp",
		Code:    ErrCodeNeedMoreSteps,
		Message: "Kode OTP tidak diterima. Silakan coba lagi.",
	}, nil
}

// ---------------------------------------------------------------------------
// Batch login
// ---------------------------------------------------------------------------

// Credential adalah pasangan username-password yang akan diproses batch.
type Credential struct {
	Username string
	Password string
}

// BatchResult adalah hasil login untuk satu kredensial dalam batch.
//
// CATATAN: kalau Result.OTPRequired == true, akun tersebut PUNYA 2FA aktif
// dan tidak bisa diselesaikan otomatis dalam batch (butuh kode dari HP
// mahasiswa secara real-time). Hasil batch untuk akun ini hanya berisi
// Flow + Devices; panggil VerifyOTP terpisah di luar batch untuk
// menyelesaikannya secara interaktif, sebelum flow itu kedaluwarsa (lihat
// otpChallengeTTL).
type BatchResult struct {
	Username string
	Result   *LoginResult
	Err      error
}

// LoginBatch memproses banyak login SECARA TERBATAS (maxConcurrent goroutine
// berjalan bersamaan), bukan langsung ribuan sekaligus. Ini penting supaya:
//   - Tidak membanjiri server UB (menghindari rate-limit/WAF/blokir IP)
//   - Tidak menghabiskan memori & file descriptor di server kita sendiri
//
// Semua login dalam satu batch berbagi sharedTransport (connection pool),
// jadi throughput tetap tinggi walau tiap login punya cookiejar terpisah.
//
// Contoh pemakaian untuk 1000 mahasiswa dengan 20 request berjalan bersamaan:
//
//	results := LoginBatch(creds, 20)
func LoginBatch(creds []Credential, maxConcurrent int) []BatchResult {
	if maxConcurrent <= 0 {
		maxConcurrent = 10
	}

	results := make([]BatchResult, len(creds))
	sem := make(chan struct{}, maxConcurrent) // semaphore pembatas concurrency
	var wg sync.WaitGroup
	wg.Add(len(creds))

	for i := range creds {
		i := i
		go func() {
			defer wg.Done()
			sem <- struct{}{}        // ambil slot; blok kalau sudah penuh
			defer func() { <-sem }() // lepas slot setelah selesai

			result, err := LoginAndGetUser(creds[i].Username, creds[i].Password)
			results[i] = BatchResult{
				Username: creds[i].Username,
				Result:   result,
				Err:      err,
			}
		}()
	}

	wg.Wait()
	return results
}

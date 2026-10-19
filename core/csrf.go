//go:build linux && amd64

package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// CSRFConfig configures the CSRF middleware returned by CSRF.
//
// TokenLength is the number of random bytes in a generated token (the cookie value is hex, so twice as long); defaults to 32.
//
//	Example: TokenLength: 32 yields a 64-character hex token.
//	Example: TokenLength: 0 uses the default of 32.
//
// CookieName is the cookie that stores the token; defaults to "csrf_token".
//
//	Example: CookieName: "_csrf".
//
// HeaderName is the request header checked for the token on unsafe methods; defaults to "X-CSRF-Token".
//
//	Example: HeaderName: "X-XSRF-Token".
//
// FormField is the urlencoded form field checked when the header is absent; defaults to "csrf_token".
//
//	Example: FormField: "authenticity_token".
//
// Secure sets the Secure flag on the token cookie so it is sent only over HTTPS;
// tokens issued on a TLS request always carry Secure.
//
//	Example: Secure: true.
//
// SameSite sets the cookie's SameSite attribute.
//
//	Example: SameSite: SameSiteStrict.
//
// MaxAge is the token cookie lifetime in seconds; defaults to 43200 (12 hours).
//
//	Example: MaxAge: 3600 expires the token after one hour.
//
// ErrorHandler runs when validation fails; when nil the middleware replies 403 "CSRF token mismatch".
//
//	Example: ErrorHandler: func(req *Request, resp *Response) { resp.Status(403).JSON([]byte(`{"error":"csrf"}`)) }.
type CSRFConfig struct {
	TokenLength    int
	CookieName     string
	HeaderName     string
	FormField      string
	Secure         bool
	SameSite       SameSite
	MaxAge         int
	ErrorHandler   func(*Request, *Response)
	TrustedOrigins []string
}

// CSRF returns middleware implementing the double-submit-cookie pattern: it issues a random token cookie, stores the token on the request (retrievable with CSRFToken), and on unsafe methods (POST, PUT, PATCH, DELETE, etc.) requires a matching token in the configured header or form field. Zero-valued CSRFConfig fields take their defaults.
//
// Example: s.Router.Use(CSRF(CSRFConfig{}))
// Example: s.Router.Use(CSRF(CSRFConfig{Secure: true, SameSite: SameSiteStrict}))
// Example: s.Router.Use(CSRF(CSRFConfig{HeaderName: "X-XSRF-Token", MaxAge: 3600}))
func CSRF(cfg CSRFConfig) MiddlewareFunc {
	if cfg.TokenLength <= 0 {
		cfg.TokenLength = 32
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "csrf_token"
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "X-CSRF-Token"
	}
	if cfg.FormField == "" {
		cfg.FormField = "csrf_token"
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 43200
	}

	tokenLen := cfg.TokenLength
	cookieName := cfg.CookieName
	headerName := cfg.HeaderName
	formField := cfg.FormField
	secure := cfg.Secure
	sameSite := cfg.SameSite
	maxAge := cfg.MaxAge
	errorHandler := cfg.ErrorHandler
	trusted := newCSRFTrustedOrigins(cfg.TrustedOrigins)

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			token := req.Cookie(cookieName)
			if token == "" {
				b := make([]byte, tokenLen)
				if _, err := rand.Read(b); err != nil {
					resp.Status(500).String("internal error")
					return
				}
				token = hex.EncodeToString(b)
				resp.SetCookie(Cookie{
					Name:     cookieName,
					Value:    token,
					Path:     "/",
					MaxAge:   maxAge,
					Secure:   secure || req.IsTLS,
					HttpOnly: false,
					SameSite: sameSite,
				})
			}

			req.Set("csrf_token", token)

			if isUnsafeMethod(req.Method) {
				if !trusted.allowsRequest(req) {
					if errorHandler != nil {
						errorHandler(req, resp)
					} else {
						resp.Status(403).String("cross-site request rejected")
					}
					return
				}
				clientToken := req.Header(headerName)
				if clientToken == "" {
					clientToken = extractFormField(req, formField)
				}

				if !constantTimeEqualString(token, clientToken) {
					if errorHandler != nil {
						errorHandler(req, resp)
					} else {
						resp.Status(403).String("CSRF token mismatch")
					}
					return
				}
			}

			next(req, resp)
		}
	}
}

type csrfTrustedOrigins map[string]struct{}

func newCSRFTrustedOrigins(origins []string) csrfTrustedOrigins {
	trusted := make(csrfTrustedOrigins, len(origins))
	for _, o := range origins {
		normalized, ok := normalizeOrigin(o)
		if !ok {
			panic(fmt.Sprintf("core: invalid CSRF trusted origin %q (want scheme://host[:port])", o))
		}
		trusted[normalized] = struct{}{}
	}
	return trusted
}

func (t csrfTrustedOrigins) contains(origin string) bool {
	if len(t) == 0 {
		return false
	}
	normalized, ok := normalizeOrigin(origin)
	if !ok {
		return false
	}
	_, found := t[normalized]
	return found
}

func (t csrfTrustedOrigins) allowsRequest(req *Request) bool {
	origin := req.Header("origin")
	switch req.Header("sec-fetch-site") {
	case "cross-site":
		return false
	case "same-site":
		return t.contains(origin)
	}
	scheme := requestScheme(req)
	self, _ := normalizeOrigin(scheme + "://" + req.Host)
	if origin != "" {
		normalized, ok := normalizeOrigin(origin)
		return ok && normalized == self || t.contains(origin)
	}
	if scheme == "https" {
		if referer := req.Header("referer"); referer != "" {
			u, err := url.Parse(referer)
			if err != nil {
				return false
			}
			refOrigin := u.Scheme + "://" + u.Host
			normalized, ok := normalizeOrigin(refOrigin)
			return ok && normalized == self || t.contains(refOrigin)
		}
	}
	return true
}

func requestScheme(req *Request) string {
	if req.IsTLS {
		return "https"
	}
	if req.peerAddr != "" {
		proto, _, _ := strings.Cut(req.Header("x-forwarded-proto"), ",")
		if EqualFoldASCII(trimASCIISpace(proto), "https") {
			return "https"
		}
	}
	return "http"
}

func normalizeOrigin(origin string) (string, bool) {
	scheme, hostport, ok := strings.Cut(origin, "://")
	if !ok || scheme == "" || hostport == "" || strings.ContainsAny(hostport, "/?#@ \t") {
		return "", false
	}
	scheme, hostport = strings.ToLower(scheme), strings.ToLower(hostport)
	switch {
	case scheme == "http" && strings.HasSuffix(hostport, ":80"):
		hostport = hostport[:len(hostport)-len(":80")]
	case scheme == "https" && strings.HasSuffix(hostport, ":443"):
		hostport = hostport[:len(hostport)-len(":443")]
	}
	return scheme + "://" + hostport, true
}

func isUnsafeMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return false
	}
	return true
}

func extractFormField(req *Request, field string) string {
	ct := req.Header("Content-Type")
	if !hasPrefixFold(ct, "application/x-www-form-urlencoded") {
		return ""
	}
	body := req.Body
	fieldBytes := []byte(field)
	fieldLen := len(fieldBytes)

	i := 0
	for i < len(body) {
		keyStart := i
		eqPos := -1
		for i < len(body) && body[i] != '&' {
			if body[i] == '=' && eqPos == -1 {
				eqPos = i
			}
			i++
		}
		if eqPos >= 0 && eqPos-keyStart == fieldLen {
			match := true
			for j := 0; j < fieldLen; j++ {
				if body[keyStart+j] != fieldBytes[j] {
					match = false
					break
				}
			}
			if match {
				valStart := eqPos + 1
				return string(body[valStart:i])
			}
		}
		i++
	}
	return ""
}

// CSRFToken returns the CSRF token associated with the current request by the CSRF middleware, for embedding in forms or response headers; it returns "" if the CSRF middleware did not run.
//
// Example: token := CSRFToken(req)
// Example: resp.SetHeader("X-CSRF-Token", CSRFToken(req))
func CSRFToken(req *Request) string {
	return req.GetString("csrf_token")
}

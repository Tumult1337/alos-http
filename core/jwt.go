//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/guno1928/turbo"
)

// JWTConfig configures the JWT middleware.
//
// Secret is the HMAC key used to verify HS256, HS384 and HS512 token signatures.
//
//	Example: Secret: []byte("my-256-bit-secret") verifies tokens signed with that key.
//
// ContextKey is the request key under which validated claims are stored; defaults to "jwt_claims" when empty.
//
//	Example: ContextKey: "user" stores claims under req.Get("user") (and also "jwt_claims").
//	Example: ContextKey: "" stores claims under "jwt_claims".
//
// TokenLookup selects where the token is read, as "source:name"; defaults to "header:Authorization" when empty. Supported sources are "header" and "query".
//
//	Example: TokenLookup: "header:Authorization" reads a "Bearer <token>" Authorization header.
//	Example: TokenLookup: "query:token" reads the token from the "token" query parameter.
type JWTConfig struct {
	Secret          []byte
	Key             crypto.PublicKey
	KeyFunc         func(kid, alg string) (any, error)
	Algorithms      []string
	Audience        []string
	Issuer          string
	Leeway          time.Duration
	AllowMissingExp bool
	ContextKey      string
	TokenLookup     string
}

var (
	ErrJWTMalformed   = errors.New("core: malformed JWT")
	ErrJWTAlg         = errors.New("core: JWT algorithm not allowed for the key")
	ErrJWTSignature   = errors.New("core: JWT signature does not verify")
	ErrJWTExpired     = errors.New("core: JWT expired")
	ErrJWTMissingExp  = errors.New("core: JWT has no exp claim")
	ErrJWTNotYetValid = errors.New("core: JWT not yet valid")
	ErrJWTAudience    = errors.New("core: JWT audience not accepted")
	ErrJWTIssuer      = errors.New("core: JWT issuer not accepted")
)

const (
	jwtAlgHS256 = "HS256"
	jwtAlgHS384 = "HS384"
	jwtAlgHS512 = "HS512"
	jwtAlgRS256 = "RS256"
	jwtAlgPS256 = "PS256"
	jwtAlgES256 = "ES256"
	jwtAlgEdDSA = "EdDSA"

	maxJWTLength       = 64 << 10
	jwtES256SigLen     = 64
	defaultJWTClaimKey = "jwt_claims"
)

var jwtB64 = base64.RawURLEncoding.Strict()

type jwtHeader struct {
	Alg  string `json:"alg"`
	Kid  string `json:"kid"`
	Crit any    `json:"crit"`
}

type jwtParts struct {
	header       jwtHeader
	signingInput string
	payload      []byte
	signature    []byte
}

// JWT returns middleware that validates a signed JWT, rejecting requests whose token is missing, malformed, or expired with HTTP 401, and stores the claims on the request per cfg.ContextKey. See JWTConfig for defaults.
//
// Example: app.Use(JWT(JWTConfig{Secret: []byte("secret")}))
// Example: app.Use(JWT(JWTConfig{Secret: key, TokenLookup: "query:token"}))
// Example: app.Use(JWT(JWTConfig{Secret: key, ContextKey: "user"}))
func JWT(cfg JWTConfig) MiddlewareFunc {
	if len(cfg.Secret) == 0 && cfg.Key == nil && cfg.KeyFunc == nil {
		panic("core: JWTConfig needs Secret, Key or KeyFunc")
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = defaultJWTClaimKey
	}

	lookupSource, lookupName := "header", "Authorization"
	if source, name, ok := strings.Cut(cfg.TokenLookup, ":"); ok {
		lookupSource, lookupName = source, name
	}
	contextKey := cfg.ContextKey

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			var token string
			switch lookupSource {
			case "header":
				auth := req.Header(lookupName)
				if len(auth) > 7 && EqualFoldASCII(auth[:7], "bearer ") {
					token = auth[7:]
				}
			case "query":
				token = req.QueryParam(lookupName)
			}
			if token == "" {
				resp.Status(401).JSONString(`{"error":"missing or invalid token"}`)
				return
			}
			claims, err := VerifyJWT(token, cfg)
			if err != nil {
				resp.Status(401).JSONString(jwtErrorBody(err))
				return
			}
			req.Set(contextKey, claims)
			if contextKey != defaultJWTClaimKey {
				req.Set(defaultJWTClaimKey, claims)
			}
			next(req, resp)
		}
	}
}

func jwtErrorBody(err error) string {
	switch err {
	case ErrJWTExpired:
		return `{"error":"token expired"}`
	case ErrJWTMissingExp:
		return `{"error":"missing exp claim"}`
	}
	return `{"error":"invalid token"}`
}

func VerifyJWT(token string, cfg JWTConfig) (map[string]any, error) {
	parts, err := splitJWT(token)
	if err != nil {
		return nil, err
	}
	key, err := jwtKey(cfg, parts.header)
	if err != nil {
		return nil, err
	}
	if !jwtAlgAllowed(cfg.Algorithms, parts.header.Alg, key) {
		return nil, ErrJWTAlg
	}
	if !verifyJWTSignature(parts.header.Alg, key, parts.signingInput, parts.signature) {
		return nil, ErrJWTSignature
	}
	var claims map[string]any
	if err := sonic.Unmarshal(parts.payload, &claims); err != nil || claims == nil {
		return nil, ErrJWTMalformed
	}
	if err := checkJWTClaims(claims, cfg, float64(turbo.UnixNano())/float64(time.Second)); err != nil {
		return nil, err
	}
	return claims, nil
}

func splitJWT(token string) (jwtParts, error) {
	var p jwtParts
	if len(token) > maxJWTLength || strings.Count(token, ".") != 2 {
		return p, ErrJWTMalformed
	}
	headerPart, rest, _ := strings.Cut(token, ".")
	payloadPart, sigPart, _ := strings.Cut(rest, ".")
	if headerPart == "" || payloadPart == "" {
		return p, ErrJWTMalformed
	}
	headerJSON, err := jwtB64.DecodeString(headerPart)
	if err != nil {
		return p, ErrJWTMalformed
	}
	if err := sonic.Unmarshal(headerJSON, &p.header); err != nil || p.header.Alg == "" || p.header.Crit != nil {
		return p, ErrJWTMalformed
	}
	if p.payload, err = jwtB64.DecodeString(payloadPart); err != nil {
		return p, ErrJWTMalformed
	}
	if p.signature, err = jwtB64.DecodeString(sigPart); err != nil {
		return p, ErrJWTMalformed
	}
	p.signingInput = token[:len(headerPart)+1+len(payloadPart)]
	return p, nil
}

func jwtKey(cfg JWTConfig, h jwtHeader) (any, error) {
	if cfg.KeyFunc != nil {
		key, err := cfg.KeyFunc(h.Kid, h.Alg)
		if err != nil || key == nil {
			return nil, ErrJWTSignature
		}
		return key, nil
	}
	if cfg.Key != nil {
		return cfg.Key, nil
	}
	if len(cfg.Secret) == 0 {
		return nil, ErrJWTAlg
	}
	return cfg.Secret, nil
}

func jwtAlgsForKey(key any) []string {
	switch k := key.(type) {
	case []byte:
		if len(k) > 0 {
			return []string{jwtAlgHS256, jwtAlgHS384, jwtAlgHS512}
		}
	case *rsa.PublicKey:
		return []string{jwtAlgRS256, jwtAlgPS256}
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			return []string{jwtAlgES256}
		}
	case ed25519.PublicKey:
		return []string{jwtAlgEdDSA}
	}
	return nil
}

func jwtAlgAllowed(configured []string, alg string, key any) bool {
	if !slices.Contains(jwtAlgsForKey(key), alg) {
		return false
	}
	return len(configured) == 0 || slices.Contains(configured, alg)
}

func verifyJWTSignature(alg string, key any, signingInput string, sig []byte) bool {
	switch alg {
	case jwtAlgHS256:
		return jwtHMACEqual(sha256.New, key.([]byte), signingInput, sig)
	case jwtAlgHS384:
		return jwtHMACEqual(sha512.New384, key.([]byte), signingInput, sig)
	case jwtAlgHS512:
		return jwtHMACEqual(sha512.New, key.([]byte), signingInput, sig)
	case jwtAlgRS256:
		digest := sha256.Sum256([]byte(signingInput))
		return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, digest[:], sig) == nil
	case jwtAlgPS256:
		digest := sha256.Sum256([]byte(signingInput))
		return rsa.VerifyPSS(key.(*rsa.PublicKey), crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
	case jwtAlgES256:
		if len(sig) != jwtES256SigLen {
			return false
		}
		digest := sha256.Sum256([]byte(signingInput))
		r := new(big.Int).SetBytes(sig[:jwtES256SigLen/2])
		s := new(big.Int).SetBytes(sig[jwtES256SigLen/2:])
		return ecdsa.Verify(key.(*ecdsa.PublicKey), digest[:], r, s)
	case jwtAlgEdDSA:
		return ed25519.Verify(key.(ed25519.PublicKey), []byte(signingInput), sig)
	}
	return false
}

func jwtHMACEqual(h func() hash.Hash, secret []byte, signingInput string, sig []byte) bool {
	mac := hmac.New(h, secret)
	mac.Write([]byte(signingInput))
	return hmac.Equal(mac.Sum(nil), sig)
}

func checkJWTClaims(claims map[string]any, cfg JWTConfig, now float64) error {
	leeway := cfg.Leeway.Seconds()
	exp, hasExp, ok := jwtNumericClaim(claims, "exp")
	switch {
	case !ok:
		return ErrJWTMalformed
	case !hasExp && !cfg.AllowMissingExp:
		return ErrJWTMissingExp
	case hasExp && now >= exp+leeway:
		return ErrJWTExpired
	}
	for _, name := range [...]string{"nbf", "iat"} {
		at, has, ok := jwtNumericClaim(claims, name)
		if !ok {
			return ErrJWTMalformed
		}
		if has && at > now+leeway {
			return ErrJWTNotYetValid
		}
	}
	if cfg.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != cfg.Issuer {
			return ErrJWTIssuer
		}
	}
	if len(cfg.Audience) > 0 && !jwtAudienceAccepted(claims["aud"], cfg.Audience) {
		return ErrJWTAudience
	}
	return nil
}

func jwtNumericClaim(claims map[string]any, name string) (value float64, present, valid bool) {
	raw, present := claims[name]
	if !present {
		return 0, false, true
	}
	value, valid = raw.(float64)
	return value, true, valid
}

func jwtAudienceAccepted(aud any, accepted []string) bool {
	switch v := aud.(type) {
	case string:
		return slices.Contains(accepted, v)
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && slices.Contains(accepted, s) {
				return true
			}
		}
	}
	return false
}

// JWTClaims returns the validated claims attached to req by the JWT middleware, or nil if none are present.
//
// Example: claims := JWTClaims(req); if claims == nil { return }
// Example: sub, _ := JWTClaims(req)["sub"].(string)
func JWTClaims(req *Request) map[string]any {
	v, ok := req.Get(defaultJWTClaimKey)
	if !ok {
		return nil
	}
	claims, _ := v.(map[string]any)
	return claims
}

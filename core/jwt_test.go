//go:build linux && amd64

package core

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"sync"
	"testing"
	"time"
)

type jwtTestKeys struct {
	secret []byte
	rsa    *rsa.PrivateKey
	ec     *ecdsa.PrivateKey
	ec384  *ecdsa.PrivateKey
	ed     ed25519.PrivateKey
}

var (
	jwtKeysOnce sync.Once
	jwtKeys     jwtTestKeys
)

func testJWTKeys(t testing.TB) jwtTestKeys {
	jwtKeysOnce.Do(func() {
		jwtKeys.secret = []byte("a-very-secret-hmac-key-for-tests")
		var err error
		if jwtKeys.rsa, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if jwtKeys.ec, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		if jwtKeys.ec384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
			panic(err)
		}
		if _, jwtKeys.ed, err = ed25519.GenerateKey(rand.Reader); err != nil {
			panic(err)
		}
	})
	return jwtKeys
}

func jwtSegment(t testing.TB, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func jwtHMAC(h func() hash.Hash, key []byte, input string) []byte {
	mac := hmac.New(h, key)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

func jwtSign(t testing.TB, alg string, key any, input string) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(input))
	switch alg {
	case "HS256":
		return jwtHMAC(sha256.New, key.([]byte), input)
	case "HS384":
		return jwtHMAC(sha512.New384, key.([]byte), input)
	case "HS512":
		return jwtHMAC(sha512.New, key.([]byte), input)
	case "RS256":
		sig, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case "PS256":
		sig, err := rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, key.(*ecdsa.PrivateKey), digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	case "EdDSA":
		return ed25519.Sign(key.(ed25519.PrivateKey), []byte(input))
	}
	return nil
}

func makeJWT(t testing.TB, header map[string]any, claims any, alg string, key any) string {
	t.Helper()
	input := jwtSegment(t, header) + "." + jwtSegment(t, claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(jwtSign(t, alg, key, input))
}

func signedJWT(t testing.TB, alg string, key any, claims map[string]any) string {
	t.Helper()
	return makeJWT(t, map[string]any{"alg": alg, "typ": "JWT"}, claims, alg, key)
}

func jwtNow() float64 { return float64(time.Now().Unix()) }

func liveClaims() map[string]any {
	return map[string]any{"sub": "user-1", "exp": jwtNow() + 600}
}

func TestJWTAlgorithms(t *testing.T) {
	k := testJWTKeys(t)
	for _, tc := range []struct {
		alg  string
		sign any
		cfg  JWTConfig
	}{
		{"HS256", k.secret, JWTConfig{Secret: k.secret}},
		{"HS384", k.secret, JWTConfig{Secret: k.secret}},
		{"HS512", k.secret, JWTConfig{Secret: k.secret}},
		{"RS256", k.rsa, JWTConfig{Key: &k.rsa.PublicKey}},
		{"PS256", k.rsa, JWTConfig{Key: &k.rsa.PublicKey}},
		{"ES256", k.ec, JWTConfig{Key: &k.ec.PublicKey}},
		{"EdDSA", k.ed, JWTConfig{Key: k.ed.Public()}},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			claims, err := VerifyJWT(signedJWT(t, tc.alg, tc.sign, liveClaims()), tc.cfg)
			if err != nil || claims["sub"] != "user-1" {
				t.Fatalf("claims %v err %v", claims, err)
			}
		})
	}
}

func TestJWTAlgorithmConfusion(t *testing.T) {
	k := testJWTKeys(t)
	rsaDER, err := x509.MarshalPKIXPublicKey(&k.rsa.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	none := jwtSegment(t, map[string]any{"alg": "none"}) + "." + jwtSegment(t, liveClaims()) + "."
	cases := []struct {
		name  string
		token string
		cfg   JWTConfig
	}{
		{"alg none against a secret", none, JWTConfig{Secret: k.secret}},
		{"alg none against an RSA key", none, JWTConfig{Key: &k.rsa.PublicKey}},
		{"HS256 keyed with the RSA public key bytes", signedJWT(t, "HS256", rsaDER, liveClaims()), JWTConfig{Key: &k.rsa.PublicKey}},
		{"RS256 against an HMAC secret", signedJWT(t, "RS256", k.rsa, liveClaims()), JWTConfig{Secret: k.secret}},
		{"ES256 against an RSA key", signedJWT(t, "ES256", k.ec, liveClaims()), JWTConfig{Key: &k.rsa.PublicKey}},
		{"EdDSA against an EC key", signedJWT(t, "EdDSA", k.ed, liveClaims()), JWTConfig{Key: &k.ec.PublicKey}},
		{"ES256 against a P-384 key", signedJWT(t, "ES256", k.ec, liveClaims()), JWTConfig{Key: &k.ec384.PublicKey}},
		{"HS256 outside the configured algorithms", signedJWT(t, "HS256", k.secret, liveClaims()), JWTConfig{Secret: k.secret, Algorithms: []string{"HS512"}}},
		{"RS256 outside the configured algorithms", signedJWT(t, "RS256", k.rsa, liveClaims()), JWTConfig{Key: &k.rsa.PublicKey, Algorithms: []string{"PS256"}}},
		{"private key passed as Key", signedJWT(t, "RS256", k.rsa, liveClaims()), JWTConfig{Key: k.rsa}},
		{"unknown algorithm", makeJWT(t, map[string]any{"alg": "HS1024"}, liveClaims(), "HS256", k.secret), JWTConfig{Secret: k.secret}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyJWT(tc.token, tc.cfg); err != ErrJWTAlg {
				t.Fatalf("err %v, want ErrJWTAlg", err)
			}
		})
	}
}

func TestJWTClaims(t *testing.T) {
	k := testJWTKeys(t)
	now := jwtNow()
	hs := func(claims map[string]any) string { return signedJWT(t, "HS256", k.secret, claims) }
	base := JWTConfig{Secret: k.secret}
	with := func(mod func(*JWTConfig)) JWTConfig {
		cfg := base
		mod(&cfg)
		return cfg
	}
	cases := []struct {
		name   string
		claims map[string]any
		cfg    JWTConfig
		want   error
	}{
		{"live token", map[string]any{"exp": now + 60}, base, nil},
		{"expired", map[string]any{"exp": now - 120}, base, ErrJWTExpired},
		{"expired within leeway", map[string]any{"exp": now - 120}, with(func(c *JWTConfig) { c.Leeway = 5 * time.Minute }), nil},
		{"expired beyond leeway", map[string]any{"exp": now - 600}, with(func(c *JWTConfig) { c.Leeway = 5 * time.Minute }), ErrJWTExpired},
		{"missing exp", map[string]any{"sub": "x"}, base, ErrJWTMissingExp},
		{"missing exp allowed", map[string]any{"sub": "x"}, with(func(c *JWTConfig) { c.AllowMissingExp = true }), nil},
		{"exp not a number", map[string]any{"exp": "tomorrow"}, base, ErrJWTMalformed},
		{"exp not a number even when optional", map[string]any{"exp": true}, with(func(c *JWTConfig) { c.AllowMissingExp = true }), ErrJWTMalformed},
		{"nbf in the future", map[string]any{"exp": now + 600, "nbf": now + 120}, base, ErrJWTNotYetValid},
		{"nbf within leeway", map[string]any{"exp": now + 600, "nbf": now + 120}, with(func(c *JWTConfig) { c.Leeway = 5 * time.Minute }), nil},
		{"nbf in the past", map[string]any{"exp": now + 600, "nbf": now - 10}, base, nil},
		{"nbf not a number", map[string]any{"exp": now + 600, "nbf": "soon"}, base, ErrJWTMalformed},
		{"iat in the future", map[string]any{"exp": now + 600, "iat": now + 120}, base, ErrJWTNotYetValid},
		{"iat in the past", map[string]any{"exp": now + 600, "iat": now - 120}, base, nil},
		{"issuer matches", map[string]any{"exp": now + 60, "iss": "https://idp.test"}, with(func(c *JWTConfig) { c.Issuer = "https://idp.test" }), nil},
		{"issuer differs", map[string]any{"exp": now + 60, "iss": "https://evil.test"}, with(func(c *JWTConfig) { c.Issuer = "https://idp.test" }), ErrJWTIssuer},
		{"issuer missing", map[string]any{"exp": now + 60}, with(func(c *JWTConfig) { c.Issuer = "https://idp.test" }), ErrJWTIssuer},
		{"audience string matches", map[string]any{"exp": now + 60, "aud": "api"}, with(func(c *JWTConfig) { c.Audience = []string{"api"} }), nil},
		{"audience list contains", map[string]any{"exp": now + 60, "aud": []string{"web", "api"}}, with(func(c *JWTConfig) { c.Audience = []string{"api", "admin"} }), nil},
		{"audience differs", map[string]any{"exp": now + 60, "aud": "web"}, with(func(c *JWTConfig) { c.Audience = []string{"api"} }), ErrJWTAudience},
		{"audience list without a match", map[string]any{"exp": now + 60, "aud": []string{"web"}}, with(func(c *JWTConfig) { c.Audience = []string{"api"} }), ErrJWTAudience},
		{"audience missing", map[string]any{"exp": now + 60}, with(func(c *JWTConfig) { c.Audience = []string{"api"} }), ErrJWTAudience},
		{"audience not a string", map[string]any{"exp": now + 60, "aud": 7}, with(func(c *JWTConfig) { c.Audience = []string{"7"} }), ErrJWTAudience},
		{"audience ignored when not configured", map[string]any{"exp": now + 60, "aud": "anything"}, base, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyJWT(hs(tc.claims), tc.cfg); err != tc.want {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}

func TestJWTKeyFunc(t *testing.T) {
	k := testJWTKeys(t)
	keys := map[string]any{"hmac-1": k.secret, "ed-1": k.ed.Public()}
	var asked []string
	cfg := JWTConfig{KeyFunc: func(kid, alg string) (any, error) {
		asked = append(asked, kid+"/"+alg)
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		return nil, errors.New("unknown kid")
	}}
	hsToken := makeJWT(t, map[string]any{"alg": "HS256", "kid": "hmac-1"}, liveClaims(), "HS256", k.secret)
	edToken := makeJWT(t, map[string]any{"alg": "EdDSA", "kid": "ed-1"}, liveClaims(), "EdDSA", k.ed)
	for _, token := range []string{hsToken, edToken} {
		if _, err := VerifyJWT(token, cfg); err != nil {
			t.Fatalf("token for a known kid: %v", err)
		}
	}
	if got := strings.Join(asked, ","); got != "hmac-1/HS256,ed-1/EdDSA" {
		t.Fatalf("KeyFunc asked for %s", got)
	}
	unknown := makeJWT(t, map[string]any{"alg": "HS256", "kid": "gone"}, liveClaims(), "HS256", k.secret)
	if _, err := VerifyJWT(unknown, cfg); err != ErrJWTSignature {
		t.Fatalf("unknown kid: %v, want ErrJWTSignature", err)
	}
	swapped := makeJWT(t, map[string]any{"alg": "HS256", "kid": "ed-1"}, liveClaims(), "HS256", k.secret)
	if _, err := VerifyJWT(swapped, cfg); err != ErrJWTAlg {
		t.Fatalf("HS256 token naming an Ed25519 kid: %v, want ErrJWTAlg", err)
	}
}

func TestJWTSignatureAndFormat(t *testing.T) {
	k := testJWTKeys(t)
	cfg := JWTConfig{Secret: k.secret}
	good := signedJWT(t, "HS256", k.secret, liveClaims())
	head, rest, _ := strings.Cut(good, ".")
	payload, sig, _ := strings.Cut(rest, ".")
	forged := jwtSegment(t, map[string]any{"sub": "admin", "exp": jwtNow() + 600})
	sigBytes, _ := base64.RawURLEncoding.DecodeString(sig)
	sigBytes[0] ^= 1
	ecToken := signedJWT(t, "ES256", k.ec, liveClaims())
	ecInput := ecToken[:strings.LastIndexByte(ecToken, '.')]
	digest := sha256.Sum256([]byte(ecInput))
	derSig, err := ecdsa.SignASN1(rand.Reader, k.ec, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	hsWithPadding := head + "." + payload + "." + sig + "="

	for _, tc := range []struct {
		name  string
		token string
		cfg   JWTConfig
		want  error
	}{
		{"payload swapped", head + "." + forged + "." + sig, cfg, ErrJWTSignature},
		{"signature bit flipped", head + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sigBytes), cfg, ErrJWTSignature},
		{"signature removed", head + "." + payload + ".", cfg, ErrJWTSignature},
		{"wrong secret", good, JWTConfig{Secret: []byte("another-secret")}, ErrJWTSignature},
		{"ES256 signature in DER form", ecInput + "." + base64.RawURLEncoding.EncodeToString(derSig), JWTConfig{Key: &k.ec.PublicKey}, ErrJWTSignature},
		{"padded signature", hsWithPadding, cfg, ErrJWTMalformed},
		{"empty", "", cfg, ErrJWTMalformed},
		{"two parts", head + "." + payload, cfg, ErrJWTMalformed},
		{"four parts", good + ".x", cfg, ErrJWTMalformed},
		{"empty header", "." + payload + "." + sig, cfg, ErrJWTMalformed},
		{"empty payload", head + ".." + sig, cfg, ErrJWTMalformed},
		{"header not base64url", "e+J9." + payload + "." + sig, cfg, ErrJWTMalformed},
		{"header not JSON", base64.RawURLEncoding.EncodeToString([]byte("alg")) + "." + payload + "." + sig, cfg, ErrJWTMalformed},
		{"header without alg", makeJWT(t, map[string]any{"typ": "JWT"}, liveClaims(), "HS256", k.secret), cfg, ErrJWTMalformed},
		{"critical header extension", makeJWT(t, map[string]any{"alg": "HS256", "crit": []string{"b64"}, "b64": false}, liveClaims(), "HS256", k.secret), cfg, ErrJWTMalformed},
		{"payload is an array", makeJWT(t, map[string]any{"alg": "HS256"}, []any{1, 2}, "HS256", k.secret), cfg, ErrJWTMalformed},
		{"payload is null", makeJWT(t, map[string]any{"alg": "HS256"}, nil, "HS256", k.secret), cfg, ErrJWTMalformed},
		{"oversized", head + "." + strings.Repeat("A", maxJWTLength) + "." + sig, cfg, ErrJWTMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyJWT(tc.token, tc.cfg); err != tc.want {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}

func TestJWTMiddleware(t *testing.T) {
	k := testJWTKeys(t)
	mw := JWT(JWTConfig{Secret: k.secret, ContextKey: "user"})
	var seen map[string]any
	h := mw(func(req *Request, resp *Response) {
		seen = JWTClaims(req)
		if v, ok := req.Get("user"); !ok || v == nil {
			t.Error("claims missing under the configured key")
		}
		resp.Status(204)
	})
	run := func(auth string) (int, string) {
		seen = nil
		req := &Request{Method: "GET", Path: "/", Headers: [][2]string{{"Authorization", auth}}}
		resp := &Response{}
		resp.Reset()
		h(req, resp)
		return resp.StatusCode, string(resp.transmittedBodyBytes())
	}
	if code, _ := run("Bearer " + signedJWT(t, "HS256", k.secret, liveClaims())); code != 204 || seen["sub"] != "user-1" {
		t.Fatalf("valid token: %d claims %v", code, seen)
	}
	for _, tc := range []struct{ auth, body string }{
		{"", `{"error":"missing or invalid token"}`},
		{"Basic abc", `{"error":"missing or invalid token"}`},
		{"Bearer " + signedJWT(t, "HS256", k.secret, map[string]any{"exp": jwtNow() - 60}), `{"error":"token expired"}`},
		{"Bearer " + signedJWT(t, "HS256", k.secret, map[string]any{"sub": "x"}), `{"error":"missing exp claim"}`},
		{"Bearer " + signedJWT(t, "HS256", []byte("other"), liveClaims()), `{"error":"invalid token"}`},
	} {
		if code, body := run(tc.auth); code != 401 || !strings.Contains(body, tc.body) || seen != nil {
			t.Errorf("auth %.30q: %d %q, want 401 %s", tc.auth, code, body, tc.body)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("JWT without a key did not panic")
		}
	}()
	JWT(JWTConfig{})
}

func FuzzJWT(f *testing.F) {
	k := testJWTKeys(f)
	claims := map[string]any{"sub": "fuzz", "exp": jwtNow() + 3600, "aud": []string{"api"}, "iss": "idp"}
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		f.Add(signedJWT(f, alg, k.secret, claims))
	}
	f.Add(signedJWT(f, "RS256", k.rsa, claims))
	f.Add(signedJWT(f, "PS256", k.rsa, claims))
	f.Add(signedJWT(f, "ES256", k.ec, claims))
	f.Add(signedJWT(f, "EdDSA", k.ed, claims))
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("a.b.c")
	f.Add("..")
	configs := []JWTConfig{
		{Secret: k.secret, Audience: []string{"api"}, Issuer: "idp"},
		{Key: &k.rsa.PublicKey},
		{Key: &k.ec.PublicKey, AllowMissingExp: true},
		{Key: k.ed.Public(), Leeway: time.Hour},
	}
	f.Fuzz(func(t *testing.T, token string) {
		for i, cfg := range configs {
			claims, err := VerifyJWT(token, cfg)
			if err != nil {
				if claims != nil {
					t.Fatalf("config %d returned claims with error %v", i, err)
				}
				continue
			}
			if claims == nil {
				t.Fatalf("config %d accepted %q without claims", i, token)
			}
			parts, perr := splitJWT(token)
			key, kerr := jwtKey(cfg, parts.header)
			if perr != nil || kerr != nil || !jwtAlgAllowed(cfg.Algorithms, parts.header.Alg, key) {
				t.Fatalf("config %d accepted alg %q", i, parts.header.Alg)
			}
		}
	})
}

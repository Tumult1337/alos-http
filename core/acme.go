//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
	"golang.org/x/crypto/acme"
)

// ACMEConfig configures automatic TLS certificate provisioning through Let's
// Encrypt (or any ACME-compatible CA), passed via Config.ACME.
//
// Email is the account contact address submitted to the ACME CA.
//
//	Example: Email: "admin@example.com".
//
// CacheDir is where account keys and the Certbot-style certificate lineage
// (live/archive/renewal directories) are persisted; defaults to
// "/etc/letsencrypt" when empty.
//
//	Example: CacheDir: "/etc/letsencrypt".
//	Example: CacheDir: "" uses the default "/etc/letsencrypt".
//
// Domains lists the hostnames to obtain and automatically renew certificates
// for via the HTTP-01 challenge.
//
//	Example: Domains: []string{"example.com", "www.example.com"}.
//
// ACMENode overrides the ACME directory URL; empty uses the Let's Encrypt
// production directory.
//
//	Example: ACMENode: "" uses Let's Encrypt production.
//	Example: ACMENode: "https://acme-staging-v02.api.letsencrypt.org/directory" uses the LE staging environment.
type ACMEConfig struct {
	Email    string
	CacheDir string
	Domains  []string
	ACMENode string
}

const (
	acmeLongWait        = 24 * time.Hour
	acmeAuthzRetryMax   = 5
	acmeRenewBefore     = 30 * 24 * time.Hour
	acmeRenewCheckEvery = 6 * time.Hour
	acmeMinWake         = time.Minute

	acmeRenewalProbeTimeout  = 2 * ariFetchTimeout
	acmeARITimeoutRetry      = 15 * time.Minute
	acmeRenewLifetimeDivisor = 3
)

var errACMEPanicked = &staticError{"ACME operation panicked"}

type acmeIntegration struct {
	server   *Server
	client   *acme.Client
	email    string
	cacheDir string
	acmeNode string

	challengeDir string

	domains     []string
	domainMu    sync.Mutex
	initialOnce sync.Once

	challenges *alosmap.TypedMap[string, *acmeChallenge]

	localIPs   atomic.Pointer[[]net.IP]
	stop       chan struct{}
	registered atomic.Bool

	schedule   acmeSchedule
	httpClient *http.Client
	now        func() time.Time
	obtainCert func(domain string) error
	sleep      func(d time.Duration) bool
}

type acmeChallenge struct {
	token string
	auth  string
}

func acmePrintf(format string, args ...any) {
	if debugFlag.Load() {
		Dbg(format, args...)
		return
	}
	lower := strings.ToLower(format)
	switch {
	case strings.Contains(lower, "failed") || strings.Contains(lower, "warning"):
		logger().Warn(fmt.Sprintf(format, args...))
	case strings.Contains(lower, "obtained cert") || strings.Contains(lower, "renewal succeeded"):
		logger().Info(fmt.Sprintf(format, args...))
	}
}

func newACMEIntegration(cfg ACMEConfig, s *Server) *acmeIntegration {
	if cfg.CacheDir == "" {
		cfg.CacheDir = "/etc/letsencrypt"
	}
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		acmePrintf("[ACME] failed to create ACME work dir %s: %v", cfg.CacheDir, err)
	}
	directoryURL := acme.LetsEncryptURL
	if cfg.ACMENode != "" {
		directoryURL = cfg.ACMENode
	}
	if err := ensureCertbotLayout(cfg.CacheDir); err != nil {
		acmePrintf("[ACME] failed to initialize Certbot-style storage under %s: %v", cfg.CacheDir, err)
	}

	challengeDir := filepath.Join(cfg.CacheDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(challengeDir, 0700); err != nil {
		acmePrintf("[ACME] failed to create challenge dir %s: %v", challengeDir, err)
	}
	acmePrintf("[ACME] cert persistence enabled; cache dir: %s", cfg.CacheDir)
	acmePrintf("[ACME] challenge dir: %s", challengeDir)

	key, err := loadOrCreateACMEAccountKey(filepath.Join(cfg.CacheDir, acmeAccountKeyFile))
	if err != nil {
		acmePrintf("[ACME] account key unavailable: %v", err)
		return nil
	}

	ai := &acmeIntegration{
		server:       s,
		email:        cfg.Email,
		cacheDir:     cfg.CacheDir,
		acmeNode:     cfg.ACMENode,
		challengeDir: challengeDir,
		domains:      cfg.Domains,
		challenges:   alosmap.NewTypedSized[string, *acmeChallenge](32, 0).Prealloc(256),
		stop:         make(chan struct{}),
		client: &acme.Client{
			Key:          key,
			DirectoryURL: directoryURL,
		},
		httpClient: &http.Client{Timeout: ariFetchTimeout},
		now:        wallNow,
	}
	ai.obtainCert = ai.obtain
	ai.sleep = ai.sleepUnlessStopped

	acmePrintf("[ACME] account email: %s", cfg.Email)
	acmePrintf("[ACME] LE directory: %s", directoryURL)
	ai.refreshLocalIPs()
	return ai
}

const acmeAccountKeyFile = "account.key"

func loadOrCreateACMEAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: not PEM", path)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an ECDSA key", path)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0600); err != nil {
		acmePrintf("[ACME] account key not persisted to %s: %v", path, err)
	}
	return key, nil
}

func (ai *acmeIntegration) refreshLocalIPs() {
	ips := gatherPublicIPv4()
	ai.localIPs.Store(&ips)
	if len(ips) == 0 {
		acmePrintf("[ACME] WARNING: no public IPv4 addresses detected on this machine")
		acmePrintf("[ACME] listing all interface addresses for debugging:")
		logAllInterfaces()
	} else {
		strs := make([]string, 0, len(ips))
		for _, ip := range ips {
			strs = append(strs, ip.String())
		}
		acmePrintf("[ACME] detected public IPs: %s", strings.Join(strs, ", "))
	}
}

func logAllInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		acmePrintf("[ACME]   interfaces error: %v", err)
		return
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			acmePrintf("[ACME]   %s: %s (flags: %v)", iface.Name, a.String(), iface.Flags)
		}
	}
}

func gatherPublicIPv4() []net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]net.IP, 0, 4)
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifaces[i].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			if isPrivateIPv4(ip4) {
				continue
			}
			out = append(out, ip4)
		}
	}
	return out
}

func isPrivateIPv4(ip net.IP) bool {
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127)
}

func (ai *acmeIntegration) domainPointsHere(domain string) bool {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		acmePrintf("[ACME] DNS lookup for %s failed: %v", domain, err)
		return false
	}
	if len(addrs) == 0 {
		acmePrintf("[ACME] DNS lookup for %s returned no records", domain)
		return false
	}

	acmePrintf("[ACME] DNS lookup for %s returned: %v", domain, addrs)

	localIPs := ai.localIPs.Load()
	if localIPs == nil || len(*localIPs) == 0 {
		acmePrintf("[ACME] no local IPs detected, cannot verify domain %s", domain)
		return false
	}

	for _, a := range addrs {
		resolved := net.ParseIP(a)
		if resolved == nil {
			continue
		}
		resolved4 := resolved.To4()
		if resolved4 == nil {
			continue
		}
		for _, lip := range *localIPs {
			if lip.Equal(resolved4) {
				acmePrintf("[ACME] %s -> %s matches local IP %s", domain, a, lip.String())
				return true
			}
		}
	}

	localStrs := make([]string, 0, len(*localIPs))
	for _, lip := range *localIPs {
		localStrs = append(localStrs, lip.String())
	}
	acmePrintf("[ACME] %s does not resolve to any local IP (domain: %v, local: %v)", domain, addrs, localStrs)
	return false
}

func (ai *acmeIntegration) HandleHTTP01(path string) ([]byte, bool) {
	const prefix = "/.well-known/acme-challenge/"
	if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
		return nil, false
	}
	token := path[len(prefix):]
	if !validACMEToken(token) {
		acmePrintf("[ACME] HTTP-01 challenge rejected: invalid token characters")
		return nil, false
	}

	acmePrintf("[ACME] HTTP-01 challenge request: token=%s", token)

	var found *acmeChallenge
	ai.challenges.Range(func(_ string, ch *acmeChallenge) bool {
		if ch.token == token {
			found = ch
			return false
		}
		return true
	})
	if found != nil {
		acmePrintf("[ACME] HTTP-01 challenge served from memory: token=%s len=%d", token, len(found.auth))
		return UnsafeBytes(found.auth), true
	}

	filePath := filepath.Join(ai.challengeDir, token)
	data, err := os.ReadFile(filePath)
	if err == nil && len(data) > 0 {
		acmePrintf("[ACME] HTTP-01 challenge served from disk: %s len=%d", filePath, len(data))
		return data, true
	}

	acmePrintf("[ACME] HTTP-01 challenge NOT FOUND: token=%s (checked memory + disk at %s)", token, filePath)
	return nil, false
}

func (ai *acmeIntegration) Start() {
	go ai.runLoop()
}

func (ai *acmeIntegration) Stop() {
	select {
	case <-ai.stop:
	default:
		close(ai.stop)
	}
}

func (ai *acmeIntegration) runLoop() {
	defer ai.recoverPanic()
	ai.primeInitial()
	for ai.sleep(ai.renewAllRecovered()) {
		ai.refreshLocalIPs()
	}
}

func (ai *acmeIntegration) recoverPanic() {
	if r := recover(); r != nil {
		ai.server.reportPanic(nil, r)
	}
}

func (ai *acmeIntegration) renewAllRecovered() (wake time.Duration) {
	wake = acmeMinWake
	defer ai.recoverPanic()
	return ai.renewAll()
}

func (ai *acmeIntegration) obtainCertRecovered(domain string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			ai.server.reportPanic(nil, r)
			err = errACMEPanicked
		}
	}()
	return ai.obtainCert(domain)
}

func (ai *acmeIntegration) sleepUnlessStopped(d time.Duration) bool {
	timer := turbo.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ai.stop:
		return false
	case <-timer.C:
		return true
	}
}

func (ai *acmeIntegration) primeInitial() {
	if ai == nil {
		return
	}
	ai.initialOnce.Do(func() {
		ai.initialObtainAll()
	})
}

func (ai *acmeIntegration) domainsSnapshot() []string {
	if ai == nil {
		return nil
	}
	ai.domainMu.Lock()
	defer ai.domainMu.Unlock()
	out := make([]string, len(ai.domains))
	copy(out, ai.domains)
	return out
}

func (ai *acmeIntegration) initialObtainAll() {
	ai.domainMu.Lock()
	domains := make([]string, len(ai.domains))
	copy(domains, ai.domains)
	ai.domainMu.Unlock()

	for _, domain := range domains {
		if ai.tryLoadCached(domain) {
			continue
		}
		go ai.obtainWithRetry(domain)
	}
}

func ensureCertbotLayout(cacheDir string) error {
	for _, dir := range []string{
		filepath.Join(cacheDir, "live"),
		filepath.Join(cacheDir, "archive"),
		filepath.Join(cacheDir, "renewal"),
	} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(cacheDir, "live", "README"), []byte(certbotLiveREADME(true)), 0644)
}

func certbotLiveREADME(isBaseDir bool) string {
	prefix := ""
	if isBaseDir {
		prefix = "[cert name]/"
	}
	return fmt.Sprintf("This directory contains your keys and certificates.\n\n%sprivkey.pem  : the private key for your certificate.\n%sfullchain.pem: the certificate file used in most server software.\n%schain.pem    : used for OCSP stapling support.\n%scert.pem     : the server certificate only.\n\nWARNING: DO NOT MOVE OR RENAME THESE FILES!\n         Certbot-style tools expect these files to remain here.\n", prefix, prefix, prefix, prefix)
}

func (ai *acmeIntegration) certbotLiveDir(domain string) string {
	return filepath.Join(ai.cacheDir, "live", domain)
}

func (ai *acmeIntegration) certbotArchiveDir(domain string) string {
	return filepath.Join(ai.cacheDir, "archive", domain)
}

func (ai *acmeIntegration) certbotRenewalPath(domain string) string {
	return filepath.Join(ai.cacheDir, "renewal", domain+".conf")
}

func (ai *acmeIntegration) tryLoadCached(domain string) bool {
	fullchainPath := filepath.Join(ai.certbotLiveDir(domain), "fullchain.pem")
	privkeyPath := filepath.Join(ai.certbotLiveDir(domain), "privkey.pem")

	certPEM, err := os.ReadFile(fullchainPath)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(privkeyPath)
	if err != nil {
		acmePrintf("[ACME] cached lineage for %s missing private key at %s: %v", domain, privkeyPath, err)
		return false
	}

	entry, err := NewCertEntryFromPEM(domain, certPEM, keyPEM, CertACME)
	if err != nil {
		acmePrintf("[ACME] failed to parse cached cert for %s: %v", domain, err)
		return false
	}
	leaf, err := validatePersistedACMECert(domain, entry)
	if err != nil {
		acmePrintf("[ACME] cached cert for %s rejected: %v", domain, err)
		return false
	}

	ai.server.certStore.AddCert(entry)
	if ai.server.config.DefaultDomain != "" {
		ai.server.certStore.SetDefault(ai.server.config.DefaultDomain)
	}
	ai.server.rebuildFallbackTLSConfig()
	acmePrintf("[ACME] loaded cached cert for %s from %s (expires %s)", domain, fullchainPath, leaf.NotAfter.Format("2006-01-02 15:04:05"))
	return true
}

func validatePersistedACMECert(domain string, entry *CertEntry) (*x509.Certificate, error) {
	if entry == nil || len(entry.ChainDER) == 0 {
		return nil, &staticError{"persisted ACME lineage is empty"}
	}
	leaf, err := x509.ParseCertificate(entry.ChainDER[0])
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, err
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, &staticError{"persisted ACME certificate has expired"}
	}
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return nil, &staticError{"persisted ACME certificate is self-signed"}
	}
	return leaf, nil
}

func nextArchiveVersion(archiveDir string) (int, error) {
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 1, nil
		}
		return 0, err
	}
	maxVersion := 0
	for _, entry := range entries {
		version := archiveVersionFromName(entry.Name())
		if version > maxVersion {
			maxVersion = version
		}
	}
	return maxVersion + 1, nil
}

func archiveVersionFromName(name string) int {
	if !strings.HasSuffix(name, ".pem") {
		return 0
	}
	base := strings.TrimSuffix(name, ".pem")
	for _, prefix := range []string{"cert", "chain", "fullchain", "privkey"} {
		if !strings.HasPrefix(base, prefix) {
			continue
		}
		version, err := strconv.Atoi(base[len(prefix):])
		if err != nil || version < 1 {
			return 0
		}
		return version
	}
	return 0
}

func writeLiveSymlink(livePath, archivePath string) error {
	if err := os.Remove(livePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	relTarget, err := filepath.Rel(filepath.Dir(livePath), archivePath)
	if err != nil {
		return err
	}
	return os.Symlink(relTarget, livePath)
}

func writeRenewalConfig(path, archiveDir, liveDir, directoryURL, webrootPath string) error {
	content := fmt.Sprintf("version = 1.0.0\narchive_dir = %s\ncert = %s\nprivkey = %s\nchain = %s\nfullchain = %s\n\n[renewalparams]\nauthenticator = webroot\nserver = %s\nkey_type = ecdsa\nwebroot_path = %s\n",
		archiveDir,
		filepath.Join(liveDir, "cert.pem"),
		filepath.Join(liveDir, "privkey.pem"),
		filepath.Join(liveDir, "chain.pem"),
		filepath.Join(liveDir, "fullchain.pem"),
		directoryURL,
		webrootPath,
	)
	return os.WriteFile(path, []byte(content), 0600)
}

func (ai *acmeIntegration) saveCertbotLineage(domain string, certPEM, chainPEM, fullchainPEM, keyPEM []byte) error {
	liveDir := ai.certbotLiveDir(domain)
	archiveDir := ai.certbotArchiveDir(domain)
	if err := os.MkdirAll(liveDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(archiveDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ai.certbotRenewalPath(domain)), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(liveDir, "README"), []byte(certbotLiveREADME(false)), 0644); err != nil {
		return err
	}

	version, err := nextArchiveVersion(archiveDir)
	if err != nil {
		return err
	}

	archiveTargets := map[string]string{
		"cert":      filepath.Join(archiveDir, fmt.Sprintf("cert%d.pem", version)),
		"chain":     filepath.Join(archiveDir, fmt.Sprintf("chain%d.pem", version)),
		"fullchain": filepath.Join(archiveDir, fmt.Sprintf("fullchain%d.pem", version)),
		"privkey":   filepath.Join(archiveDir, fmt.Sprintf("privkey%d.pem", version)),
	}
	if err := os.WriteFile(archiveTargets["cert"], certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(archiveTargets["chain"], chainPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(archiveTargets["fullchain"], fullchainPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(archiveTargets["privkey"], keyPEM, 0600); err != nil {
		return err
	}

	for kind, archivePath := range archiveTargets {
		if err := writeLiveSymlink(filepath.Join(liveDir, kind+".pem"), archivePath); err != nil {
			return err
		}
	}

	return writeRenewalConfig(ai.certbotRenewalPath(domain), archiveDir, liveDir, ai.client.DirectoryURL, ai.cacheDir)
}

func isTransientACMEAuthorizationLookupError(err error) bool {
	acmeErr, ok := err.(*acme.Error)
	if !ok {
		return false
	}
	if acmeErr.StatusCode != 404 && acmeErr.StatusCode != 400 {
		return false
	}
	return strings.Contains(strings.ToLower(acmeErr.Detail), "no such authorization")
}

func (ai *acmeIntegration) getAuthorizationWithRetry(ctx context.Context, orderURL, domain string, authzIndex int, authzURL string) (*acme.Authorization, error) {
	currentURL := authzURL
	for attempt := 1; attempt <= acmeAuthzRetryMax; attempt++ {
		authz, err := ai.client.GetAuthorization(ctx, currentURL)
		if err == nil {
			return authz, nil
		}
		if !isTransientACMEAuthorizationLookupError(err) || attempt == acmeAuthzRetryMax {
			return nil, err
		}

		acmePrintf("[ACME] authorization for %s not ready yet (attempt %d/%d): %v", domain, attempt, acmeAuthzRetryMax, err)
		if orderURL != "" {
			order, orderErr := ai.client.GetOrder(ctx, orderURL)
			if orderErr != nil {
				acmePrintf("[ACME] failed to refresh order %s while waiting for authorization: %v", orderURL, orderErr)
			} else if authzIndex >= 0 && authzIndex < len(order.AuthzURLs) && order.AuthzURLs[authzIndex] != "" && order.AuthzURLs[authzIndex] != currentURL {
				acmePrintf("[ACME] authorization URL for %s updated: %s -> %s", domain, currentURL, order.AuthzURLs[authzIndex])
				currentURL = order.AuthzURLs[authzIndex]
			}
		}

		delay := time.Duration(attempt) * 500 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, &staticError{"authorization lookup retries exhausted"}
}

func (ai *acmeIntegration) obtainWithRetry(domain string) {
	defer ai.recoverPanic()
	for failures := 0; ; {
		if !ai.domainPointsHere(domain) {
			acmePrintf("[ACME] %s does not point to this machine, will retry in 24h", domain)
			if !ai.sleep(acmeLongWait) {
				return
			}
			ai.refreshLocalIPs()
			continue
		}
		acmePrintf("[ACME] obtaining cert for %s (attempt %d)", domain, failures+1)
		err := ai.obtainCertRecovered(domain)
		if err == nil {
			return
		}
		failures++
		delay := acmeRetryDelay(err, failures)
		acmePrintf("[ACME] attempt %d for %s FAILED: %v; retrying in %s", failures, domain, err, delay.Round(time.Second))
		if !ai.sleep(delay) {
			return
		}
		ai.refreshLocalIPs()
	}
}

func (ai *acmeIntegration) ensureRegistered(ctx context.Context) error {
	if ai.registered.Load() {
		return nil
	}
	acct := &acme.Account{}
	if ai.email != "" {
		acct.Contact = []string{"mailto:" + ai.email}
	}
	acmePrintf("[ACME] registering account with Let's Encrypt...")
	_, err := ai.client.Register(ctx, acct, acme.AcceptTOS)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "already") || strings.Contains(errStr, "existing") || strings.Contains(errStr, "conflict") {
			acmePrintf("[ACME] account already registered (ok)")
		} else {
			if acmeErr, ok := err.(*acme.Error); ok && acmeErr.StatusCode == 409 {
				acmePrintf("[ACME] account already registered (409, ok)")
			} else {
				acmePrintf("[ACME] registration failed: %v", err)
				return err
			}
		}
	} else {
		acmePrintf("[ACME] account registered successfully")
	}
	ai.registered.Store(true)
	return nil
}

func (ai *acmeIntegration) obtain(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := ai.ensureRegistered(ctx); err != nil {
		return err
	}

	acmePrintf("[ACME] creating order for %s...", domain)
	order, err := ai.client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		acmePrintf("[ACME] authorize order failed for %s: %v", domain, err)
		return err
	}
	acmePrintf("[ACME] order created: status=%s authz=%d url=%s", order.Status, len(order.AuthzURLs), order.URI)

	for i, authzURL := range order.AuthzURLs {
		acmePrintf("[ACME] processing authorization %d/%d: %s", i+1, len(order.AuthzURLs), authzURL)
		authz, err := ai.getAuthorizationWithRetry(ctx, order.URI, domain, i, authzURL)
		if err != nil {
			acmePrintf("[ACME] get authorization failed: %v", err)
			return err
		}
		acmePrintf("[ACME] authorization status: %s", authz.Status)
		if authz.Status == acme.StatusValid {
			acmePrintf("[ACME] authorization already valid, skipping")
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			acmePrintf("[ACME]   available challenge: type=%s status=%s", c.Type, c.Status)
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			acmePrintf("[ACME] no http-01 challenge offered for %s", domain)
			return &staticError{"no http-01 challenge offered for " + domain}
		}

		if !validACMEToken(chal.Token) {
			acmePrintf("[ACME] CA offered an http-01 token outside the base64url alphabet for %s", domain)
			return &staticError{"invalid http-01 token offered for " + domain}
		}

		keyAuth, err := ai.client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			acmePrintf("[ACME] computing challenge response failed: %v", err)
			return err
		}
		acmePrintf("[ACME] challenge token: %s", chal.Token)
		acmePrintf("[ACME] key authorization length: %d", len(keyAuth))

		ai.challenges.Store(domain, &acmeChallenge{
			token: chal.Token,
			auth:  keyAuth,
		})

		tokenFile := filepath.Join(ai.challengeDir, chal.Token)
		if err := os.WriteFile(tokenFile, []byte(keyAuth), 0600); err != nil {
			acmePrintf("[ACME] WARNING: failed to write challenge file %s: %v", tokenFile, err)
		} else {
			acmePrintf("[ACME] wrote challenge file: %s", tokenFile)
		}

		acmePrintf("[ACME] challenge ready at http://%s/.well-known/acme-challenge/%s", domain, chal.Token)
		acmePrintf("[ACME] accepting challenge, telling LE to validate...")

		if _, err := ai.client.Accept(ctx, chal); err != nil {
			acmePrintf("[ACME] accept challenge failed: %v", err)
			ai.cleanupChallenge(domain, chal.Token)
			return err
		}

		acmePrintf("[ACME] waiting for LE validation...")
		finalAuthz, err := ai.client.WaitAuthorization(ctx, authzURL)
		if err != nil {
			acmePrintf("[ACME] authorization FAILED for %s: %v", domain, err)
			ai.cleanupChallenge(domain, chal.Token)
			return err
		}
		acmePrintf("[ACME] authorization succeeded: status=%s", finalAuthz.Status)
		ai.cleanupChallenge(domain, chal.Token)
	}

	if order.URI != "" {
		acmePrintf("[ACME] waiting for order %s to become ready...", order.URI)
		order, err = ai.client.WaitOrder(ctx, order.URI)
		if err != nil {
			acmePrintf("[ACME] order wait failed for %s: %v", domain, err)
			return err
		}
		acmePrintf("[ACME] order ready for %s: status=%s", domain, order.Status)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return err
	}

	acmePrintf("[ACME] finalizing order for %s...", domain)
	der, _, err := ai.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		acmePrintf("[ACME] finalize order failed for %s: %v", domain, err)
		return err
	}
	acmePrintf("[ACME] received %d certificate(s) in chain", len(der))

	var certBuf []byte
	for _, d := range der {
		certBuf = append(certBuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[0]})
	var chainPEM []byte
	for _, d := range der[1:] {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}

	keyBytes, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	entry, err := NewCertEntryFromPEM(domain, certBuf, keyPEM, CertACME)
	if err != nil {
		acmePrintf("[ACME] failed to parse obtained cert for %s: %v", domain, err)
		return err
	}
	if err := ai.saveCertbotLineage(domain, certPEM, chainPEM, certBuf, keyPEM); err != nil {
		acmePrintf("[ACME] WARNING: failed to persist cert lineage for %s under %s: %v", domain, ai.cacheDir, err)
	} else {
		acmePrintf("[ACME] persisted cert lineage for %s under %s", domain, ai.certbotLiveDir(domain))
	}
	ai.server.certStore.AddCert(entry)
	if ai.server.config.DefaultDomain != "" {
		ai.server.certStore.SetDefault(ai.server.config.DefaultDomain)
	}
	ai.server.rebuildFallbackTLSConfig()

	leaf, _ := x509.ParseCertificate(der[0])
	acmePrintf("[ACME] installed fresh in-memory cert for %s", domain)
	if leaf != nil {
		acmePrintf("[ACME] OBTAINED cert for %s (expires %s, issuer: %s)", domain, leaf.NotAfter.Format("2006-01-02 15:04:05"), leaf.Issuer.CommonName)
	} else {
		acmePrintf("[ACME] OBTAINED cert for %s", domain)
	}
	return nil
}

func validACMEToken(token string) bool {
	if token == "" {
		return false
	}
	for i := 0; i < len(token); i++ {
		c := token[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (ai *acmeIntegration) cleanupChallenge(domain, token string) {
	ai.challenges.Delete(domain)
	if !validACMEToken(token) {
		return
	}
	tokenFile := filepath.Join(ai.challengeDir, token)
	if err := os.Remove(tokenFile); err != nil && !os.IsNotExist(err) {
		acmePrintf("[ACME] WARNING: failed to remove challenge file %s: %v", tokenFile, err)
	}
}

func (ai *acmeIntegration) renewDomainOnce(domain string, st *acmeRenewalState) time.Duration {
	err := ai.obtainCertRecovered(domain)
	ai.schedule.mu.Lock()
	defer ai.schedule.mu.Unlock()
	if err != nil {
		delay := st.recordFailure(err, ai.now())
		acmePrintf("[ACME] renewal FAILED for %s: %v; retrying in %s", domain, err, delay.Round(time.Second))
		return delay
	}
	st.recordSuccess()
	acmePrintf("[ACME] renewal SUCCEEDED for %s", domain)
	return 0
}

func (ai *acmeIntegration) renewAll() time.Duration {
	acmePrintf("[ACME] renewal check started")
	nextWake := acmeRenewCheckEvery
	ai.server.certStore.certs.Range(func(domain string, entry *CertEntry) bool {
		if entry.Source != CertACME || len(entry.ChainDER) == 0 {
			return true
		}
		leaf, err := x509.ParseCertificate(entry.ChainDER[0])
		if err != nil {
			acmePrintf("[ACME] failed to parse cert for %s during renewal check: %v", domain, err)
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), acmeRenewalProbeTimeout)
		st, renewAt, nextPoll := ai.renewalTime(ctx, domain, leaf)
		cancel()
		now := ai.now()
		if !nextPoll.IsZero() {
			nextWake = min(nextWake, nextPoll.Sub(now))
		}
		if wait := renewAt.Sub(now); wait > 0 {
			acmePrintf("[ACME] cert for %s OK (expires %s, renewal at %s)", domain, leaf.NotAfter.Format("2006-01-02"), renewAt.Format(time.RFC3339))
			nextWake = min(nextWake, wait)
			return true
		}
		acmePrintf("[ACME] cert for %s NEEDS RENEWAL (expires %s)", domain, leaf.NotAfter.Format("2006-01-02"))
		if retry := ai.renewDomainOnce(domain, st); retry > 0 {
			nextWake = min(nextWake, retry)
		}
		return true
	})
	acmePrintf("[ACME] renewal check complete")
	return max(nextWake, acmeMinWake)
}

func (ai *acmeIntegration) renewalInfoEndpoint(ctx context.Context) string {
	ai.schedule.mu.Lock()
	read, url := ai.schedule.directoryRead, ai.schedule.renewalInfoURL
	ai.schedule.mu.Unlock()
	if read {
		return url
	}
	url, err := fetchRenewalInfoURL(ctx, ai.httpClient, ai.client.DirectoryURL)
	if err != nil {
		acmePrintf("[ACME] WARNING: reading the ACME directory for renewalInfo failed: %v", err)
		return ""
	}
	ai.schedule.mu.Lock()
	ai.schedule.renewalInfoURL, ai.schedule.directoryRead = url, true
	ai.schedule.mu.Unlock()
	return url
}

func (ai *acmeIntegration) renewalTime(ctx context.Context, domain string, leaf *x509.Certificate) (st *acmeRenewalState, renewAt, nextPoll time.Time) {
	infoURL := ai.renewalInfoEndpoint(ctx)
	certID, hasID := ariCertID(leaf)
	now := ai.now()
	ai.schedule.mu.Lock()
	st = ai.schedule.state(domain)
	if st.certID != certID {
		*st = acmeRenewalState{certID: certID}
	}
	pollDue := infoURL != "" && hasID && !now.Before(st.nextPoll)
	ai.schedule.mu.Unlock()

	var window ariWindow
	var poll time.Duration
	var err error
	if pollDue {
		window, poll, err = fetchRenewalWindow(ctx, ai.httpClient, infoURL, certID, now)
	}

	ai.schedule.mu.Lock()
	defer ai.schedule.mu.Unlock()
	if pollDue && err != nil {
		acmePrintf("[ACME] WARNING: renewalInfo for %s failed: %v", domain, err)
		st.nextPoll = now.Add(ariDefaultPoll)
		if errors.Is(err, context.DeadlineExceeded) {
			st.nextPoll = now.Add(acmeARITimeoutRetry)
		}
	} else if pollDue {
		if st.renewAt.IsZero() || !window.contains(st.renewAt) {
			st.renewAt = window.pick()
		}
		st.nextPoll = now.Add(poll)
	}
	renewAt = st.renewAt
	if renewAt.IsZero() {
		renewAt = leaf.NotAfter.Add(-acmeRenewBefore)
	} else if latest := latestRenewal(leaf); renewAt.After(latest) {
		renewAt = latest
	}
	if st.retryAt.After(renewAt) {
		renewAt = st.retryAt
	}
	return st, renewAt, st.nextPoll
}

func latestRenewal(leaf *x509.Certificate) time.Time {
	margin := min(acmeRenewBefore, leaf.NotAfter.Sub(leaf.NotBefore)/acmeRenewLifetimeDivisor)
	return leaf.NotAfter.Add(-margin)
}

func (ai *acmeIntegration) addDomain(domain string) {
	ai.domainMu.Lock()
	for _, d := range ai.domains {
		if d == domain {
			ai.domainMu.Unlock()
			acmePrintf("[ACME] domain %s already managed", domain)
			return
		}
	}
	ai.domains = append(ai.domains, domain)
	ai.domainMu.Unlock()

	acmePrintf("[ACME] added domain %s for ACME management", domain)
	if ai.tryLoadCached(domain) {
		return
	}
	go func() {
		ai.obtainWithRetry(domain)
	}()
}

// GetCertificate returns the TLS certificate registered for the
// ClientHello's SNI, implementing the tls.Config.GetCertificate callback
// signature. It returns ErrNoCertForSNI if no matching or default
// certificate is registered.
func (ai *acmeIntegration) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	entry := ai.server.certStore.Lookup(hello.ServerName)
	if entry != nil {
		return &entry.TLSCert, nil
	}
	return nil, ErrNoCertForSNI
}

// AddDomainCert is an alias for AddCert.
//
// Example: err := srv.AddDomainCert("example.com", certPEM, keyPEM)
func (s *Server) AddDomainCert(domain string, certPEM, keyPEM []byte) error {
	return s.AddCert(domain, certPEM, keyPEM)
}

// AddACMEDomain registers domain for automatic ACME certificate management,
// initializing the server's ACME integration on first use with the optional
// email as the account contact. It is safe to call before or after
// EnableACME.
//
// Example: srv.AddACMEDomain("example.com")
// Example: srv.AddACMEDomain("example.com", "admin@example.com")
func (s *Server) AddACMEDomain(domain string, email ...string) {
	if cur := s.acme.Load(); cur != nil {
		cur.addDomain(domain)
		return
	}
	e := ""
	if len(email) > 0 {
		e = email[0]
	}
	ai := newACMEIntegration(ACMEConfig{Email: e, Domains: []string{domain}}, s)
	if ai == nil {
		return
	}
	s.replaceACME(ai)
	ai.Start()
}

// EnableACME starts automatic TLS certificate provisioning for cfg.Domains
// through ACME, replacing any existing ACME integration on the server.
//
// Example: srv.EnableACME(core.ACMEConfig{Email: "admin@example.com", Domains: []string{"example.com"}})
func (s *Server) EnableACME(cfg ACMEConfig) {
	ai := newACMEIntegration(cfg, s)
	if ai == nil {
		return
	}
	s.replaceACME(ai)
	ai.Start()
}

func (s *Server) replaceACME(ai *acmeIntegration) {
	if old := s.acme.Swap(ai); old != nil && old != ai {
		old.Stop()
	}
}

// LocalIPs returns the server's detected public IPv4 addresses, used to
// verify that a domain's DNS points at this machine before requesting an
// ACME certificate.
func (s *Server) LocalIPs() []net.IP {
	ai := s.acme.Load()
	if ai == nil {
		return gatherPublicIPv4()
	}
	p := ai.localIPs.Load()
	if p == nil {
		return nil
	}
	return *p
}

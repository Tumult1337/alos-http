//go:build linux && amd64

package core

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/crypto/ocsp"
)

const (
	tlsExtStatusRequest    = 0x0005
	ocspStatusTypeOCSP     = 1
	tlsHSCertificateStatus = 22

	ocspFetchTimeout       = 10 * time.Second
	ocspRetryMin           = time.Minute
	ocspRetryMax           = time.Hour
	maxOCSPResponseLen     = 16 << 10
	ocspClockSkew          = 5 * time.Minute
	ocspRequestContentType = "application/ocsp-request"
)

var (
	errOCSPNoIssuer    = errors.New("ocsp: the certificate chain has no issuer certificate")
	errOCSPNotGood     = errors.New("ocsp: certificate status is not good")
	errOCSPExpired     = errors.New("ocsp: response has no nextUpdate in the future")
	errOCSPNotYetValid = errors.New("ocsp: response thisUpdate is in the future")
	errOCSPResponder   = errors.New("ocsp: delegated responder certificate lacks the OCSP signing usage")
	errOCSPTooLarge    = errors.New("ocsp: response exceeds the size limit")
	errOCSPHTTPStatus  = errors.New("ocsp: responder returned a non-200 status")
)

type ocspStaple struct {
	der          []byte
	nextUpdateNs int64
	certMsg13    []byte
	status12     []byte
}

func appendOCSPStatus(dst, der []byte) []byte {
	dst = append(dst, ocspStatusTypeOCSP, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
	return append(dst, der...)
}

func newOCSPStaple(chain [][]byte, resp *ocsp.Response) *ocspStaple {
	status := appendOCSPStatus(nil, resp.Raw)
	return &ocspStaple{
		der:          resp.Raw,
		nextUpdateNs: resp.NextUpdate.UnixNano(),
		certMsg13:    buildCertificate13(chain, status),
		status12:     tls12Handshake(tlsHSCertificateStatus, status),
	}
}

func validateOCSPStaple(der []byte, leaf, issuer *x509.Certificate, now time.Time) (*ocsp.Response, error) {
	if len(der) > maxOCSPResponseLen {
		return nil, errOCSPTooLarge
	}
	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return nil, fmt.Errorf("ocsp: %w", err)
	}
	if resp.Certificate != nil && !resp.Certificate.Equal(issuer) && !slices.Contains(resp.Certificate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
		return nil, errOCSPResponder
	}
	if resp.Status != ocsp.Good {
		return nil, errOCSPNotGood
	}
	if resp.NextUpdate.IsZero() || !now.Before(resp.NextUpdate) {
		return nil, errOCSPExpired
	}
	if now.Add(ocspClockSkew).Before(resp.ThisUpdate) {
		return nil, errOCSPNotYetValid
	}
	return resp, nil
}

func (entry *CertEntry) leafAndIssuer() (*x509.Certificate, *x509.Certificate, error) {
	if len(entry.ChainDER) < 2 {
		return nil, nil, errOCSPNoIssuer
	}
	leaf, err := x509.ParseCertificate(entry.ChainDER[0])
	if err != nil {
		return nil, nil, err
	}
	issuer, err := x509.ParseCertificate(entry.ChainDER[1])
	if err != nil {
		return nil, nil, err
	}
	return leaf, issuer, nil
}

func (entry *CertEntry) SetOCSPStaple(der []byte) error {
	leaf, issuer, err := entry.leafAndIssuer()
	if err != nil {
		return err
	}
	resp, err := validateOCSPStaple(bytes.Clone(der), leaf, issuer, wallNow())
	if err != nil {
		return err
	}
	entry.staple.Store(newOCSPStaple(entry.ChainDER, resp))
	return nil
}

func (entry *CertEntry) loadOCSPStapleFile(path string) error {
	if path == "" {
		return nil
	}
	der, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := entry.SetOCSPStaple(der); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func (entry *CertEntry) OCSPStaple() []byte {
	if st := entry.liveStaple(); st != nil {
		return st.der
	}
	return nil
}

func (entry *CertEntry) liveStaple() *ocspStaple {
	st := entry.staple.Load()
	if st == nil || turbo.UnixNano() >= st.nextUpdateNs {
		return nil
	}
	return st
}

func (entry *CertEntry) stapleFor(ch *ParsedClientHello) *ocspStaple {
	if !ch.statusRequest {
		return nil
	}
	return entry.liveStaple()
}

func (entry *CertEntry) certificate13(st *ocspStaple) []byte {
	if st != nil {
		return st.certMsg13
	}
	return entry.cachedCertMsg
}

type ocspStapler struct {
	client *http.Client
	store  *CertStore
	done   <-chan struct{}
}

func newOCSPStapler(store *CertStore, done <-chan struct{}) *ocspStapler {
	return &ocspStapler{client: &http.Client{Timeout: ocspFetchTimeout}, store: store, done: done}
}

func (o *ocspStapler) track(entry *CertEntry) {
	leaf, issuer, err := entry.leafAndIssuer()
	if err != nil || len(leaf.OCSPServer) == 0 {
		return
	}
	go o.run(entry, leaf, issuer)
}

func (o *ocspStapler) run(entry *CertEntry, leaf, issuer *x509.Certificate) {
	retry := ocspRetryMin
	for o.current(entry) {
		wait := retry
		if resp, err := o.fetch(leaf, issuer); err == nil {
			entry.staple.Store(newOCSPStaple(entry.ChainDER, resp))
			retry = ocspRetryMin
			wait = ocspRefreshDelay(resp, wallNow())
		} else {
			retry = min(2*retry, ocspRetryMax)
		}
		if !o.sleep(wait) {
			return
		}
	}
}

func (o *ocspStapler) current(entry *CertEntry) bool {
	e, ok := o.store.certs.Load(entry.Domain)
	return ok && e == entry
}

func (o *ocspStapler) sleep(d time.Duration) bool {
	t := turbo.NewTimer(d)
	select {
	case <-t.C:
		return true
	case <-o.done:
		t.Stop()
		return false
	}
}

func ocspRefreshDelay(resp *ocsp.Response, now time.Time) time.Duration {
	midpoint := resp.ThisUpdate.Add(resp.NextUpdate.Sub(resp.ThisUpdate) / 2)
	return max(midpoint.Sub(now), ocspRetryMin)
}

func (o *ocspStapler) fetch(leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, url := range leaf.OCSPServer {
		resp, err := o.fetchFrom(url, req, leaf, issuer)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (o *ocspStapler) fetchFrom(url string, req []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	httpResp, err := o.client.Post(url, ocspRequestContentType, bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return nil, errOCSPHTTPStatus
	}
	der, err := io.ReadAll(io.LimitReader(httpResp.Body, maxOCSPResponseLen+1))
	if err != nil {
		return nil, err
	}
	if len(der) > maxOCSPResponseLen {
		return nil, errOCSPTooLarge
	}
	return validateOCSPStaple(der, leaf, issuer, wallNow())
}

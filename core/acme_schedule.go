//go:build linux && amd64

package core

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bytedance/sonic"
	"github.com/guno1928/turbo"
	"golang.org/x/crypto/acme"
)

const (
	acmeBackoffBase          = 5 * time.Minute
	acmeBackoffMax           = 24 * time.Hour
	acmeBackoffJitterDivisor = 10
	ariMinPoll               = time.Minute
	ariMaxPoll               = 24 * time.Hour
	ariDefaultPoll           = 6 * time.Hour
	ariFetchTimeout          = 30 * time.Second
	maxARIResponseBytes      = 64 << 10
)

var (
	errARIStatus = errors.New("acme: renewalInfo request failed")
	errARIWindow = errors.New("acme: renewalInfo has no valid suggestedWindow")
)

func acmeRetryDelay(err error, failures int) time.Duration {
	if wait, ok := acme.RateLimit(err); ok && wait > 0 {
		return min(wait, acmeBackoffMax)
	}
	delay := acmeBackoffBase
	for i := 1; i < failures && delay < acmeBackoffMax; i++ {
		delay *= 2
	}
	delay = min(delay, acmeBackoffMax)
	spread := int64(delay) / acmeBackoffJitterDivisor
	return delay + time.Duration(turbo.Int64(-spread, spread+1))
}

func ariCertID(leaf *x509.Certificate) (string, bool) {
	if leaf == nil || len(leaf.AuthorityKeyId) == 0 || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() < 0 {
		return "", false
	}
	serial := leaf.SerialNumber.Bytes()
	if len(serial) == 0 || serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial), true
}

type ariWindow struct {
	start, end time.Time
}

func (w ariWindow) contains(t time.Time) bool { return !t.Before(w.start) && t.Before(w.end) }

func (w ariWindow) pick() time.Time {
	return w.start.Add(time.Duration(turbo.Int64(0, int64(w.end.Sub(w.start)))))
}

func ariGetJSON(ctx context.Context, client *http.Client, url string, v any) (http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, ariFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errARIStatus
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxARIResponseBytes))
	if err != nil {
		return nil, err
	}
	return resp.Header, sonic.Unmarshal(body, v)
}

func fetchRenewalInfoURL(ctx context.Context, client *http.Client, directoryURL string) (string, error) {
	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if _, err := ariGetJSON(ctx, client, directoryURL, &dir); err != nil {
		return "", err
	}
	return dir.RenewalInfo, nil
}

func fetchRenewalWindow(ctx context.Context, client *http.Client, renewalInfoURL, certID string, now time.Time) (ariWindow, time.Duration, error) {
	var info struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
	}
	header, err := ariGetJSON(ctx, client, strings.TrimSuffix(renewalInfoURL, "/")+"/"+certID, &info)
	if err != nil {
		return ariWindow{}, 0, err
	}
	w := ariWindow{start: info.SuggestedWindow.Start, end: info.SuggestedWindow.End}
	if w.start.IsZero() || !w.end.After(w.start) {
		return ariWindow{}, 0, errARIWindow
	}
	return w, ariPollInterval(header.Get("Retry-After"), now), nil
}

func ariPollInterval(retryAfter string, now time.Time) time.Duration {
	var wait time.Duration
	if secs, err := strconv.ParseInt(retryAfter, 10, 64); err == nil && secs >= 0 {
		wait = time.Duration(min(secs, int64(ariMaxPoll/time.Second))) * time.Second
	} else if at, err := http.ParseTime(retryAfter); err == nil {
		wait = at.Sub(now)
	} else {
		return ariDefaultPoll
	}
	return min(max(wait, ariMinPoll), ariMaxPoll)
}

type acmeRenewalState struct {
	certID   string
	renewAt  time.Time
	nextPoll time.Time
	failures int
	retryAt  time.Time
}

type acmeSchedule struct {
	mu             sync.Mutex
	states         map[string]*acmeRenewalState
	renewalInfoURL string
	directoryRead  bool
}

func (s *acmeSchedule) state(domain string) *acmeRenewalState {
	if s.states == nil {
		s.states = make(map[string]*acmeRenewalState)
	}
	st := s.states[domain]
	if st == nil {
		st = &acmeRenewalState{}
		s.states[domain] = st
	}
	return st
}

func (st *acmeRenewalState) recordFailure(err error, now time.Time) time.Duration {
	st.failures++
	delay := acmeRetryDelay(err, st.failures)
	st.retryAt = now.Add(delay)
	return delay
}

func (st *acmeRenewalState) recordSuccess() {
	st.failures = 0
	st.retryAt = time.Time{}
}

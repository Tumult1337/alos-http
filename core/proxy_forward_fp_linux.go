//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
)

const fpProxyBufferLimit = 65536

var (
	fpProxyOnce   sync.Once
	fpProxyClient *fpClient
	fpProxyErr    error
)

func proxyUpstreamClient() (*fpClient, error) {
	fpProxyOnce.Do(func() {
		fpProxyClient, fpProxyErr = fpNew(fpConfig{})
	})
	return fpProxyClient, fpProxyErr
}

func fpProxyScheme(b *backend) string {
	if b.TLS {
		return "https"
	}
	return "http"
}

func fpProxyAuthority(addr string) string {
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	return strings.TrimSuffix(addr, "/")
}

func fpProxyPath(req *Request) string {
	if req.Query == "" {
		return req.Path
	}
	return req.Path + "?" + req.Query
}

func fpProxyHostHeader(req *Request, cfg *DomainConfig) string {
	if cfg.HostHeader != "" {
		return cfg.HostHeader
	}
	if cfg.PreserveHost {
		return req.Host
	}
	return ""
}

func fpProxyRequestHeaders(req *Request) [][2]string {
	out := make([][2]string, 0, len(req.Headers)+forwardingHeaderCount)
	nominated := connectionNominations(req.Headers)
	for _, h := range req.Headers {
		if isProxyFilteredHeaderFold(h[0]) || isHopByHopFold(h[0]) || nominated.nominates(h[0]) {
			continue
		}
		out = append(out, h)
	}
	return appendForwardingHeaderPairs(out, req)
}

func relayableResponseHeaders(headers [][2]string) [][2]string {
	out := make([][2]string, 0, len(headers))
	for _, h := range headers {
		if isHopByHopFold(h[0]) ||
			EqualFoldASCII(h[0], "content-length") ||
			EqualFoldASCII(h[0], "content-type") {
			continue
		}
		out = append(out, h)
	}
	return out
}

func fpResponseContentType(headers [][2]string) string {
	for _, h := range headers {
		if EqualFoldASCII(h[0], "content-type") {
			return h[1]
		}
	}
	return ""
}

func fpResponseContentLength(headers [][2]string) int64 {
	for _, header := range headers {
		if EqualFoldASCII(header[0], "transfer-encoding") {
			return -1
		}
	}
	for _, header := range headers {
		if EqualFoldASCII(header[0], "content-length") {
			length, err := strconv.ParseUint(header[1], 10, 63)
			if err != nil {
				return -1
			}
			return int64(length)
		}
	}
	return -1
}

func fpAttemptError(err error, wroteRequest, gotResponse bool) *proxyAttemptError {
	return &proxyAttemptError{
		err:          err,
		wroteRequest: wroteRequest,
		gotResponse:  gotResponse,
		timeout:      errors.Is(err, errFPTimeout),
	}
}

// forwardRequestFP is the epoll backed replacement for forwardRequest. It
// keeps the same signature so the call site can switch between them.
func (pe *ProxyEngine) forwardRequestFP(req *Request, resp *Response, b *backend, cfg *DomainConfig, target proxyCacheTarget) error {
	client, err := proxyUpstreamClient()
	if err != nil {
		return err
	}

	host := stripPort(req.Host)
	cacheableMethod := req.Method == "GET" || req.Method == "HEAD"
	autoCacheAllowed := target.storable && cacheableMethod && proxyCacheRequestAllowed(req)
	cache := pe.activeCache()
	cacheGen := cache.purgeGeneration()

	pipe := newRespPipe()
	ex, loop, err := client.start(&UpstreamRequest{
		ensureResponseDate: true,

		Scheme:      fpProxyScheme(b),
		Authority:   fpProxyAuthority(b.Addr),
		Method:      req.Method,
		Path:        fpProxyPath(req),
		HostHeader:  fpProxyHostHeader(req, cfg),
		Headers:     fpProxyRequestHeaders(req),
		Body:        req.Body,
		SkipVerify:  b.TLSSkipVerify,
		trust:       b.trust,
		DialTimeout: cfg.ConnectTimeout,
		ReadTimeout: cfg.ReadTimeout,
	}, nil, pipe)
	if err != nil {
		return fpAttemptError(err, false, false)
	}
	body := &UpstreamBody{pipe: pipe, ex: ex, loop: loop}
	defer body.Close()
	status, headers, err := pipe.waitHead()
	if err != nil {
		<-ex.done
		return fpAttemptError(err, ex.wroteRequest, false)
	}
	respHeaders := relayableResponseHeaders(headers)
	contentType := fpResponseContentType(headers)
	length := fpResponseContentLength(headers)
	if length < 0 || length > fpProxyBufferLimit {
		sw := req.StreamWriter
		if sw == nil {
			sw = resp.ensureSW()
		}
		if sw != nil {
			if length >= 0 {
				respHeaders = append(respHeaders, [2]string{"Content-Length", strconv.FormatInt(length, 10)})
			}
			if err := relayUpstreamBody(sw, body, status, respHeaders, contentType); err != nil {
				return fpAttemptError(err, true, true)
			}
			return nil
		}
	}
	buffered, err := readUpstreamBody(body, client.cfg.MaxResponseBody)
	if err != nil {
		return fpAttemptError(err, true, true)
	}

	resp.Status(status)
	if contentType != "" {
		resp.ContentType = contentType
	}
	for i := range respHeaders {
		resp.SetHeader(respHeaders[i][0], respHeaders[i][1])
	}
	if len(buffered) > 0 {
		copy(resp.prepareBody(len(buffered)), buffered)
	}

	if autoCacheAllowed && cache != nil && proxyCacheResponseAllowed(respHeaders) {
		cache.put(req.Method, host, target.path, status, respHeaders, contentType, buffered, cachePutOptions{generation: cacheGen})
	}
	return nil
}

func relayUpstreamBody(sw StreamWriter, body *UpstreamBody, status int, headers [][2]string, contentType string) error {
	if err := sw.WriteHeader(status, headers, contentType); err != nil {
		return err
	}
	bp := LargeBufPool.Get().(*[]byte)
	defer putBoxedBufCapped(&LargeBufPool, bp, largeBufPoolMaxCap)
	buf := (*bp)[:cap(*bp)]
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if werr := sw.WriteChunk(buf[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := sw.Flush(); err != nil {
		return err
	}
	return sw.Close()
}

func readUpstreamBody(body *UpstreamBody, limit int) ([]byte, error) {
	var buffered []byte
	var chunk [16 << 10]byte
	for {
		n, err := body.Read(chunk[:])
		if n > limit-len(buffered) {
			return nil, errFPBodyTooLarge
		}
		buffered = append(buffered, chunk[:n]...)
		if err == io.EOF {
			return buffered, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

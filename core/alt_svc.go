//go:build linux && amd64

package core

import (
	"bytes"
	"strconv"
)

const (
	altSvcHeaderName = "alt-svc"
	altSvcMaxAge     = 86400
)

var h1HeaderTerminator = []byte("\r\n\r\n")

type altSvcHeader struct {
	field [2]string
	h1    []byte
	hpack []byte
}

func newAltSvcHeader(port int) *altSvcHeader {
	value := "h3=\":" + strconv.Itoa(port) + "\"; ma=" + strconv.Itoa(altSvcMaxAge)
	enc := HpackEncoder{}
	enc.EncodeHeaderFold(altSvcHeaderName, value)
	return &altSvcHeader{
		field: [2]string{"Alt-Svc", value},
		h1:    []byte("Alt-Svc: " + value + "\r\n"),
		hpack: enc.Buf,
	}
}

func (s *Server) enableAltSvc(port int) {
	if s.config.DisableAltSvc || port <= 0 {
		return
	}
	s.rootFastMu.Lock()
	s.altSvc.Store(newAltSvcHeader(port))
	s.h2RootFast.Store(s.attachAltSvc(s.h2RootFast.Load()))
	s.plainRootFast.Store(s.attachPlainAltSvc(s.plainRootFast.Load()))
	s.rootFastMu.Unlock()
}

func (s *Server) attachAltSvc(fast *h2RootFastResponse) *h2RootFastResponse {
	alt := s.altSvc.Load()
	if fast == nil || alt == nil || fast.handlerAltSvc {
		return fast
	}
	withAlt := *fast
	header := make([]byte, 0, len(fast.headerPayload)+len(alt.hpack))
	header = append(append(header, fast.headerPayload...), alt.hpack...)
	withAlt.withAltSvc = newH2RootFastResponse(header, fast.body)
	withAlt.withAltSvc.refreshDate = fast.refreshDate
	return &withAlt
}

func (s *Server) attachPlainAltSvc(fast *plainRootFastResponse) *plainRootFastResponse {
	alt := s.altSvc.Load()
	if fast == nil || alt == nil || fast.handlerAltSvc {
		return fast
	}
	withAlt := *fast
	withAlt.tlsKeepAlive = injectH1HeaderLine(fast.getKeepAlive, alt.h1)
	withAlt.tlsClose = injectH1HeaderLine(fast.getClose, alt.h1)
	return &withAlt
}

func injectH1HeaderLine(response, line []byte) []byte {
	end := bytes.Index(response, h1HeaderTerminator)
	if end < 0 {
		return nil
	}
	split := end + len(h1HeaderTerminator)/2
	out := make([]byte, 0, len(response)+len(line))
	out = append(out, response[:split]...)
	out = append(out, line...)
	return append(out, response[split:]...)
}

func (f *plainRootFastResponse) bytesFor(keepAlive, tls bool) []byte {
	if tls && f.tlsKeepAlive != nil {
		if keepAlive {
			return f.tlsKeepAlive
		}
		return f.tlsClose
	}
	if keepAlive {
		return f.getKeepAlive
	}
	return f.getClose
}

func (f *h2RootFastResponse) forConn(tls bool) *h2RootFastResponse {
	if tls && f.withAltSvc != nil {
		return f.withAltSvc
	}
	return f
}

func (s *Server) altSvcFor(tls bool) *altSvcHeader {
	if !tls || s == nil {
		return nil
	}
	return s.altSvc.Load()
}

func addAltSvcHeader(resp *Response, s *Server) {
	if alt := s.altSvcFor(true); alt != nil && !headersHaveFold(resp.Headers, altSvcHeaderName) {
		resp.Headers = append(resp.Headers, alt.field)
	}
}

func appendAltSvcHPACK(dst []byte, alt *altSvcHeader, headers [][2]string) []byte {
	if alt == nil || headersHaveFold(headers, altSvcHeaderName) {
		return dst
	}
	return append(dst, alt.hpack...)
}

func headersHaveFold(headers [][2]string, name string) bool {
	for i := range headers {
		if EqualFoldASCII(headers[i][0], name) {
			return true
		}
	}
	return false
}

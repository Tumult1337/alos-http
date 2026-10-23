//go:build linux && amd64

package core

import "strconv"

const (
	altSvcHeaderName = "alt-svc"
	altSvcMaxAge     = 86400
)

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
	s.altSvc.Store(newAltSvcHeader(port))
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

//go:build linux && amd64

package core

const (
	headerXForwardedFor   = "X-Forwarded-For"
	headerXForwardedProto = "X-Forwarded-Proto"
	headerXForwardedHost  = "X-Forwarded-Host"
	headerForwarded       = "Forwarded"
	forwardingHeaderCount = 4

	forwardedProtoHTTPS = "https"
	forwardedProtoHTTP  = "http"

	forwardedForPrefix           = headerForwarded + ": for="
	forwardedHostLinePrefix      = headerXForwardedHost + ": "
	forwardedHostLineSuffix      = "\r\n" + forwardedForPrefix
	forwardedHostParamSuffix     = "\""
	forwardedProtoLineHTTPS      = headerXForwardedProto + ": " + forwardedProtoHTTPS + "\r\n"
	forwardedProtoLineHTTP       = headerXForwardedProto + ": " + forwardedProtoHTTP + "\r\n"
	forwardedProtoParamHTTPS     = ";proto=" + forwardedProtoHTTPS
	forwardedProtoParamHTTP      = ";proto=" + forwardedProtoHTTP
	forwardedProtoHostParamHTTPS = forwardedProtoParamHTTPS + ";host=\""
	forwardedProtoHostParamHTTP  = forwardedProtoParamHTTP + ";host=\""
)

type forwardingFacts struct {
	client   string
	clientOK bool
	clientV6 bool
	hostOK   bool
	tls      bool
}

func newForwardingFacts(req *Request) forwardingFacts {
	client, clientOK, clientV6 := splitForwardableIP(req.RemoteAddr)
	return forwardingFacts{
		client:   client,
		clientOK: clientOK,
		clientV6: clientV6,
		hostOK:   req.Host != "" && ValidateHost(req.Host),
		tls:      req.IsTLS,
	}
}

func appendForwardingHeaders(dst []byte, req *Request) []byte {
	f := newForwardingFacts(req)
	lineStart := len(dst)
	dst = append(dst, headerXForwardedFor+": "...)
	valueStart := len(dst)
	dst = f.appendXForwardedFor(dst, req)
	if len(dst) == valueStart {
		dst = dst[:lineStart]
	} else {
		dst = append(dst, "\r\n"...)
	}
	dst = append(dst, f.protoLine()...)
	if f.hostOK {
		dst = append(dst, forwardedHostLinePrefix...)
		dst = append(dst, req.Host...)
		dst = append(dst, forwardedHostLineSuffix...)
	} else {
		dst = append(dst, forwardedForPrefix...)
	}
	dst = f.appendForwardedNode(dst)
	dst = f.appendForwardedParams(dst, req)
	return append(dst, "\r\n"...)
}

func appendForwardingHeaderPairs(dst [][2]string, req *Request) [][2]string {
	f := newForwardingFacts(req)
	if xff := f.appendXForwardedFor(nil, req); len(xff) > 0 {
		dst = append(dst, [2]string{headerXForwardedFor, string(xff)})
	}
	dst = append(dst, [2]string{headerXForwardedProto, f.proto()})
	if f.hostOK {
		dst = append(dst, [2]string{headerXForwardedHost, req.Host})
	}
	return append(dst, [2]string{headerForwarded, string(f.appendForwarded(nil, req))})
}

func (f *forwardingFacts) proto() string {
	if f.tls {
		return forwardedProtoHTTPS
	}
	return forwardedProtoHTTP
}

func (f *forwardingFacts) protoLine() string {
	if f.tls {
		return forwardedProtoLineHTTPS
	}
	return forwardedProtoLineHTTP
}

var ipLiteralChar = func() (table [256]bool) {
	for _, c := range []byte("0123456789abcdefABCDEF.:") {
		table[c] = true
	}
	return table
}()

func forwardableIP(ip string) bool {
	if ip == "" {
		return false
	}
	for i := 0; i < len(ip); i++ {
		if !ipLiteralChar[ip[i]] {
			return false
		}
	}
	return true
}

func splitForwardableIP(addr string) (ip string, forwardable, v6 bool) {
	if len(addr) > 0 && addr[0] == '[' {
		ip = extractIP(addr)
		return ip, forwardableIP(ip), indexByte(ip, ':') >= 0
	}
	colons, lastColon, firstBad := 0, -1, len(addr)
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if c == ':' {
			colons++
			lastColon = i
		}
		if !ipLiteralChar[c] && i < firstBad {
			firstBad = i
		}
	}
	ip = addr
	if colons == 1 {
		ip = addr[:lastColon]
	}
	return ip, ip != "" && firstBad >= len(ip), colons > 1
}

func (f *forwardingFacts) appendXForwardedFor(dst []byte, req *Request) []byte {
	if req.peerAddr == "" {
		if f.clientOK {
			dst = append(dst, f.client...)
		}
		return dst
	}
	peer := extractIP(req.peerAddr)
	prior := trimASCIISpace(req.Header("x-forwarded-for"))
	switch {
	case prior != "" && !containsCRLF(prior):
		dst = append(dst, prior...)
		dst = append(dst, ", "...)
	case f.clientOK && f.client != peer:
		dst = append(dst, f.client...)
		dst = append(dst, ", "...)
	}
	if forwardableIP(peer) {
		return append(dst, peer...)
	}
	return dst
}

func (f *forwardingFacts) appendForwarded(dst []byte, req *Request) []byte {
	dst = append(dst, "for="...)
	dst = f.appendForwardedNode(dst)
	return f.appendForwardedParams(dst, req)
}

func (f *forwardingFacts) appendForwardedNode(dst []byte) []byte {
	switch {
	case !f.clientOK:
		return append(dst, "unknown"...)
	case f.clientV6:
		dst = append(dst, "\"["...)
		dst = append(dst, f.client...)
		return append(dst, "]\""...)
	}
	return append(dst, f.client...)
}

func (f *forwardingFacts) appendForwardedParams(dst []byte, req *Request) []byte {
	if !f.hostOK {
		if f.tls {
			return append(dst, forwardedProtoParamHTTPS...)
		}
		return append(dst, forwardedProtoParamHTTP...)
	}
	if f.tls {
		dst = append(dst, forwardedProtoHostParamHTTPS...)
	} else {
		dst = append(dst, forwardedProtoHostParamHTTP...)
	}
	dst = append(dst, req.Host...)
	return append(dst, forwardedHostParamSuffix...)
}

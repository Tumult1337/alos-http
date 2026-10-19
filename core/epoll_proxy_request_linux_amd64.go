//go:build linux && amd64

package core

import (
	"net/netip"
	"strconv"
)

// Responses are relayed byte for byte, so the backend must not compress
// beyond what this proxy is prepared to forward.
const proxyAcceptEncodingIdentity = "Accept-Encoding: identity\r\n"

// appendProxyRequest serialises the upstream request for a proxied exchange.
// It is the single place where client-controlled bytes are filtered before
// they reach a backend, so every header name and value is checked for CRLF and
// the hop-by-hop and forwarding headers are rewritten rather than relayed.
func appendProxyRequest(dst []byte, req *Request, hostHeader string) []byte {
	dst = append(dst, req.Method...)
	dst = append(dst, ' ')
	dst = append(dst, proxyRequestTarget(req)...)
	dst = append(dst, " HTTP/1.1\r\n"...)

	dst = append(dst, "Host: "...)
	if containsCRLF(hostHeader) {
		hostHeader = ""
	}
	dst = append(dst, hostHeader...)
	dst = append(dst, "\r\n"...)

	headersStart := len(dst)
	var nominated connectionTokens
	upgrade := ""
	for {
		collecting := len(nominated.names) == 0
		for _, h := range req.Headers {
			if isProxyFilteredHeaderFold(h[0]) || nominated.nominates(h[0]) {
				continue
			}
			if isHopByHopFold(h[0]) {
				if collecting {
					nominated.addIfConnection(h[0], h[1])
					if upgrade == "" && headerNameIs(h[0], "upgrade") && h[1] != "" && !containsCRLF(h[1]) {
						upgrade = h[1]
					}
				}
				continue
			}
			if containsCRLF(h[0]) || containsCRLF(h[1]) {
				continue
			}
			dst = append(dst, h[0]...)
			dst = append(dst, ": "...)
			dst = append(dst, h[1]...)
			dst = append(dst, "\r\n"...)
		}
		if !collecting || len(nominated.names) == 0 {
			break
		}
		dst = dst[:headersStart]
	}

	dst = appendForwardingHeaders(dst, req)
	// Connection and Upgrade are hop-by-hop and were filtered above. An upgrade
	// has to be re-stated for this hop or the backend never answers 101 and the
	// tunnel is never established.
	if upgrade != "" {
		dst = append(dst, proxyAcceptEncodingIdentity+"Connection: Upgrade\r\nUpgrade: "...)
		dst = append(dst, upgrade...)
		dst = append(dst, "\r\n"...)
	} else {
		// The client's own connection choice is never the backend's business:
		// relaying "close" would retire a pooled upstream connection per request.
		dst = append(dst, proxyAcceptEncodingIdentity+"Connection: keep-alive\r\n"...)
	}

	if len(req.Body) > 0 || req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH" {
		dst = append(dst, "Content-Length: "...)
		dst = strconv.AppendInt(dst, int64(len(req.Body)), 10)
		dst = append(dst, "\r\n"...)
	}
	dst = append(dst, "\r\n"...)
	return append(dst, req.Body...)
}

// proxyRequestTarget prefers the untouched request target so escaped path
// segments survive the hop, falling back to the parsed path and query.
func proxyRequestTarget(req *Request) string {
	target := req.RawPath
	if target == "" {
		target = req.Path
		if req.Query != "" {
			target = req.Path + "?" + req.Query
		}
	}
	if target == "" || containsCRLF(target) {
		return "/"
	}
	return target
}

// resolveAuthority splits a backend authority into an address and port.
func resolveAuthority(authority string) (netip.Addr, uint16, error) {
	host, port, err := splitAuthority(authority, "http")
	if err != nil {
		return netip.Addr{}, 0, errFPDialFailed
	}
	addr, err := fpResolve(host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return addr, port, nil
}

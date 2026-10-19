//go:build linux && amd64

package core

import (
	"bytes"
	"sync/atomic"
	"testing"
)

const tlsEpollFixH3PublicDomain = "public.test"

func tlsEpollFixH3Response(t *testing.T, handshakeDomain string) (handlerRuns int64, body []byte) {
	t.Helper()
	var runs atomic.Int64
	p := newQUICTestPeer(t, func(r *Router) {
		r.GET("/secret", func(req *Request, resp *Response) {
			runs.Add(1)
			resp.Status(200).String("secret")
		})
	})
	require := RequireAndVerifyClientCert
	for _, domain := range []string{tlsEpollFixH3PublicDomain, "a.test"} {
		if err := p.srv.AddSelfSignedCert(domain); err != nil {
			t.Fatal(err)
		}
	}
	p.srv.clientAuthByHost = clientAuthOverrides([]CertConfig{{Domain: "a.test", ClientAuth: &require}})
	p.qc.tlsCertEntry = p.srv.certStore.Lookup(handshakeDomain)
	p.send(quicStreamBytes(0, 0, h3TestRequest("/secret"), true))
	got := p.awaitSent("response FIN", func(f quicSentFrames) bool {
		for _, s := range f.streams {
			if s.streamID == 0 && s.fin {
				return true
			}
		}
		return false
	})
	for _, s := range got.streams {
		if s.streamID == 0 {
			body = append(body, s.data...)
		}
	}
	return runs.Load(), body
}

func TestTLSEpollFixH3RejectsAuthorityOutsideHandshakePolicy(t *testing.T) {
	runs, body := tlsEpollFixH3Response(t, tlsEpollFixH3PublicDomain)
	if runs != 0 || !bytes.Contains(body, []byte("Misdirected Request")) {
		t.Fatalf("authority a.test over a %s handshake: handler runs=%d response=%q, want 421 without running the handler", tlsEpollFixH3PublicDomain, runs, body)
	}
	runs, body = tlsEpollFixH3Response(t, "a.test")
	if runs != 1 || !bytes.Contains(body, []byte("secret")) {
		t.Fatalf("authority a.test over its own handshake: handler runs=%d response=%q, want the handler response", runs, body)
	}
}

//go:build linux && amd64

package core

func (pe *ProxyEngine) forwardRequest(req *Request, resp *Response, b *backend, cfg *DomainConfig, target proxyCacheTarget) error {
	if req.Header("Upgrade") != "" {
		return pe.forwardUpgrade(req, resp, b, cfg)
	}
	return pe.forwardRequestFP(req, resp, b, cfg, target)
}

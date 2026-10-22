//go:build linux && amd64

package core

import (
	"net/http"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

const (
	staticCompressMinSize    = 256
	staticCompressLargeSize  = 1 << 20
	staticBrotliLevel        = 11
	staticBrotliLevelLarge   = 9
	staticGzipLevel          = 9
	staticCompressQueueSize  = 256
	staticVariantOverhead    = 128
	staticVaryAcceptEncoding = "Accept-Encoding"
)

type staticVariant struct {
	body       []byte
	encoding   string
	validators contentValidators
}

type staticVariants struct {
	brotli *staticVariant
	gzip   *staticVariant
	cost   int64
}

type staticVariantSlot struct {
	id    staticFileID
	state atomic.Pointer[staticVariants]
}

type staticCompressJob struct {
	entry *staticCacheEntry
	slot  *staticVariantSlot
	fd    *staticFD
}

var (
	staticVariantsBuilding = &staticVariants{}
	staticVariantsNone     = &staticVariants{}
	staticVariantsRetired  = &staticVariants{}
	staticCompressSlot     = make(chan struct{}, 1)
)

func staticCompressibleType(contentType string) bool {
	mediaType, _, _ := strings.Cut(contentType, ";")
	if strings.HasPrefix(mediaType, "text/") {
		return true
	}
	switch mediaType {
	case "application/javascript", "application/json", "application/xml", "application/wasm",
		"image/svg+xml", "image/x-icon", "font/ttf", "font/otf":
		return true
	}
	return false
}

func (c *staticFileCache) compressible(e *staticCacheEntry) bool {
	return c.compressQueue != nil && e.size >= staticCompressMinSize && e.size <= c.maxFileSize && staticCompressibleType(e.contentType)
}

func (c *staticFileCache) variantFor(e *staticCacheEntry, req *Request) *staticVariant {
	if !e.compressible {
		return nil
	}
	return c.negotiateVariant(e, req)
}

func (c *staticFileCache) negotiateVariant(e *staticCacheEntry, req *Request) *staticVariant {
	accept := req.Header("Accept-Encoding")
	if accept == "" || req.Header("Range") != "" {
		return nil
	}
	w := parseAcceptEncoding(accept)
	brotliOK, gzipOK := w.accepts(w.brotli), w.accepts(w.gzip)
	if !brotliOK && !gzipOK {
		return nil
	}
	slot := e.slot.Load()
	if slot == nil {
		if slot = c.slotFor(e); slot == nil {
			return nil
		}
	}
	v := slot.state.Load()
	switch v {
	case nil:
		c.requestVariants(e, slot)
		return nil
	case staticVariantsRetired:
		e.slot.CompareAndSwap(slot, nil)
		return nil
	}
	var best *staticVariant
	if brotliOK && v.brotli != nil {
		best = v.brotli
	}
	if gzipOK && v.gzip != nil && (best == nil || len(v.gzip.body) < len(best.body)) {
		best = v.gzip
	}
	return best
}

func (c *staticFileCache) currentVersion(e *staticCacheEntry) bool {
	cur, ok := c.entries.Load(e.key)
	return ok && cur.id == e.id
}

func (c *staticFileCache) slotFor(e *staticCacheEntry) *staticVariantSlot {
	if c.variantSlots == nil || !c.currentVersion(e) {
		return nil
	}
	slot, ok := c.variantSlots.Load(e.key)
	if !ok || slot.id != e.id {
		fresh := &staticVariantSlot{id: e.id}
		switch {
		case ok:
			if !c.variantSlots.CompareAndSwap(e.key, slot, fresh) {
				return nil
			}
			c.retireSlot(slot)
		default:
			if existing, loaded := c.variantSlots.LoadOrStore(e.key, fresh); loaded {
				if existing.id != e.id {
					return nil
				}
				fresh = existing
			}
		}
		slot = fresh
		if !c.currentVersion(e) {
			c.dropSlot(e.key, slot)
			return nil
		}
	}
	e.slot.Store(slot)
	return slot
}

func (c *staticFileCache) retireSlot(slot *staticVariantSlot) {
	if prev := slot.state.Swap(staticVariantsRetired); prev != nil {
		c.bytes.Add(-prev.cost)
	}
}

func (c *staticFileCache) dropSlot(key string, slot *staticVariantSlot) {
	if c.variantSlots.CompareAndDelete(key, slot) {
		c.retireSlot(slot)
	}
}

func (c *staticFileCache) retireVariants(e *staticCacheEntry) {
	if c.variantSlots == nil || !e.compressible || c.currentVersion(e) {
		return
	}
	if slot, ok := c.variantSlots.Load(e.key); ok && slot.id == e.id {
		c.dropSlot(e.key, slot)
	}
}

func (c *staticFileCache) requestVariants(e *staticCacheEntry, slot *staticVariantSlot) {
	if !slot.state.CompareAndSwap(nil, staticVariantsBuilding) {
		return
	}
	job := staticCompressJob{entry: e, slot: slot}
	if e.data == nil {
		h := e.fd.Load()
		if h == nil || h == staticFDRetired || !h.tryAcquire() {
			slot.state.CompareAndSwap(staticVariantsBuilding, nil)
			return
		}
		job.fd = h
	}
	select {
	case c.compressQueue <- job:
	default:
		if job.fd != nil {
			job.fd.release()
		}
		slot.state.CompareAndSwap(staticVariantsBuilding, nil)
		return
	}
	if c.compressing.CompareAndSwap(false, true) {
		go c.drainCompressQueue()
	}
}

func (c *staticFileCache) drainCompressQueue() {
	for {
		select {
		case job := <-c.compressQueue:
			c.buildVariants(job)
		default:
			c.compressing.Store(false)
			if len(c.compressQueue) == 0 || !c.compressing.CompareAndSwap(false, true) {
				return
			}
		}
	}
}

func (c *staticFileCache) buildVariants(job staticCompressJob) {
	e, slot := job.entry, job.slot
	c.builds.Add(1)
	staticCompressSlot <- struct{}{}
	defer func() { <-staticCompressSlot }()
	data := e.data
	if job.fd != nil {
		data = readStaticEntryFD(job.fd, e)
		job.fd.release()
	}
	v := &staticVariants{}
	if data != nil {
		brotliLevel := staticBrotliLevel
		if len(data) > staticCompressLargeSize {
			brotliLevel = staticBrotliLevelLarge
		}
		v.brotli = e.newVariant(compressOnce(data, encodingBrotli, brotliLevel), contentEncodingNames[encodingBrotli], "-br")
		v.gzip = e.newVariant(compressOnce(data, encodingGzip, staticGzipLevel), contentEncodingNames[encodingGzip], "-gz")
	}
	if v.brotli == nil && v.gzip == nil {
		slot.state.CompareAndSwap(staticVariantsBuilding, staticVariantsNone)
		return
	}
	v.cost = staticVariantOverhead
	for _, variant := range [...]*staticVariant{v.brotli, v.gzip} {
		if variant != nil {
			v.cost += int64(len(variant.body))
		}
	}
	if !c.reserveFree(v.cost) {
		slot.state.CompareAndSwap(staticVariantsBuilding, staticVariantsNone)
		return
	}
	if !slot.state.CompareAndSwap(staticVariantsBuilding, v) {
		c.bytes.Add(-v.cost)
	}
}

func readStaticEntryFD(h *staticFD, e *staticCacheEntry) []byte {
	data, ok := preadFull(h.fd, e.size)
	if !ok {
		return nil
	}
	var st unix.Stat_t
	if unix.Fstat(h.fd, &st) != nil || staticFileIDOf(&st) != e.id {
		return nil
	}
	return data
}

func (e *staticCacheEntry) newVariant(body []byte, encoding, etagSuffix string) *staticVariant {
	if body == nil {
		return nil
	}
	validators := e.validators
	validators.etag = validators.etag[:len(validators.etag)-1] + etagSuffix + `"`
	return &staticVariant{body: body, encoding: encoding, validators: validators}
}

func (e *staticCacheEntry) serveVariant(req *Request, resp *Response, v *staticVariant) {
	if _, ok := e.plan(req, resp, &v.validators); !ok {
		return
	}
	resp.Headers = append(resp.Headers, [2]string{"content-encoding", v.encoding})
	resp.StatusCode = http.StatusOK
	resp.setBodyNoCopy(v.body, e.contentType)
	resp.fileBody = true
}

func (e *staticCacheEntry) addVary(resp *Response) {
	if e.compressible {
		resp.Headers = append(resp.Headers, [2]string{"vary", staticVaryAcceptEncoding})
	}
}

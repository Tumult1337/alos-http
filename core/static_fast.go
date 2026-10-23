//go:build linux && amd64

package core

import (
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	staticCacheDefaultMaxBytes  = 32 << 20
	staticCacheDefaultFileShare = 4
	staticCacheEvictingFileSize = 256 << 10
	staticCacheMaxFDs           = 1024
	staticFDSendMin             = 32 << 10
	staticFDEntryAndCallerRefs  = 2
	staticCacheEntryOverhead    = 256
	staticCacheSettleWindow     = 2 * time.Second
	staticCacheDefaultTTL       = 2 * time.Second
	staticScratchPathCap        = 256
	staticFileOpenFlags         = unix.O_RDONLY | unix.O_CLOEXEC
	staticProbeOpenFlags        = unix.O_PATH | unix.O_CLOEXEC
	staticFileResolveFlags      = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS
	staticDirOpenFlags          = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
)

type staticFileID struct {
	dev   uint64
	ino   uint64
	size  int64
	mtime unix.Timespec
	ctime unix.Timespec
}

func staticFileIDOf(st *unix.Stat_t) staticFileID {
	return staticFileID{dev: st.Dev, ino: st.Ino, size: st.Size, mtime: st.Mtim, ctime: st.Ctim}
}

func (id *staticFileID) settled(nowUnixNano int64) bool {
	return nowUnixNano-id.ctime.Nano() > int64(staticCacheSettleWindow)
}

type statFileInfo struct {
	name string
	st   unix.Stat_t
}

func (fi *statFileInfo) Name() string { return fi.name }

func (fi *statFileInfo) Size() int64 { return fi.st.Size }

func (fi *statFileInfo) Mode() fs.FileMode {
	mode := fs.FileMode(fi.st.Mode & uint32(fs.ModePerm))
	switch fi.st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	default:
		mode |= fs.ModeIrregular
	}
	return mode
}

func (fi *statFileInfo) ModTime() time.Time { return time.Unix(fi.st.Mtim.Sec, fi.st.Mtim.Nsec) }

func (fi *statFileInfo) IsDir() bool { return fi.st.Mode&unix.S_IFMT == unix.S_IFDIR }

func (fi *statFileInfo) Sys() any { return &fi.st }

type staticFD struct {
	fd   int
	refs atomic.Int64
}

func (h *staticFD) tryAcquire() bool {
	for {
		n := h.refs.Load()
		if n <= 0 {
			return false
		}
		if h.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (h *staticFD) release() {
	if h.refs.Add(-1) == 0 {
		_ = unix.Close(h.fd)
	}
}

var staticFDRetired = &staticFD{fd: -1}

type staticDirHandle struct {
	staticFD
	dev uint64
	ino uint64
}

type staticScratch struct {
	st   unix.Stat_t
	how  unix.OpenHow
	path []byte
}

var staticScratchPool = sync.Pool{New: func() any { return &staticScratch{path: make([]byte, 0, staticScratchPathCap)} }}

func syscallFD(fd int) uintptr { return uintptr(fd) }

func (sc *staticScratch) statPathZ(pathZ []byte) bool {
	_, _, errno := unix.Syscall6(unix.SYS_NEWFSTATAT, syscallFD(unix.AT_FDCWD), uintptr(unsafe.Pointer(&pathZ[0])), uintptr(unsafe.Pointer(&sc.st)), 0, 0, 0)
	return errno == 0
}

func (sc *staticScratch) openDirHandle(pathZ []byte) *staticDirHandle {
	fd, _, errno := unix.Syscall6(unix.SYS_OPENAT, syscallFD(unix.AT_FDCWD), uintptr(unsafe.Pointer(&pathZ[0])), staticDirOpenFlags, 0, 0, 0)
	if errno != 0 {
		return nil
	}
	if unix.Fstat(int(fd), &sc.st) != nil {
		_ = unix.Close(int(fd))
		return nil
	}
	d := &staticDirHandle{staticFD: staticFD{fd: int(fd)}, dev: sc.st.Dev, ino: sc.st.Ino}
	d.refs.Store(1)
	return d
}

func (sc *staticScratch) openBeneath(dirfd int, rel string, flags uint64) (int, unix.Errno) {
	sc.path = append(append(sc.path[:0], rel...), 0)
	sc.how = unix.OpenHow{Flags: flags, Resolve: staticFileResolveFlags}
	for {
		fd, _, errno := unix.Syscall6(unix.SYS_OPENAT2, syscallFD(dirfd), uintptr(unsafe.Pointer(&sc.path[0])), uintptr(unsafe.Pointer(&sc.how)), unsafe.Sizeof(sc.how), 0, 0)
		if errno == unix.EINTR {
			continue
		}
		if errno != 0 {
			return -1, errno
		}
		return int(fd), 0
	}
}

func (root *staticRoot) acquireDir(sc *staticScratch) *staticDirHandle {
	if !sc.statPathZ(root.absZ) {
		return nil
	}
	dev, ino := sc.st.Dev, sc.st.Ino
	for {
		cur := root.dir.Load()
		if cur != nil && cur.dev == dev && cur.ino == ino {
			if cur.tryAcquire() {
				return cur
			}
			continue
		}
		fresh := sc.openDirHandle(root.absZ)
		if fresh == nil {
			return nil
		}
		if !root.dir.CompareAndSwap(cur, fresh) {
			fresh.release()
			continue
		}
		if cur != nil {
			cur.release()
		}
		if fresh.tryAcquire() {
			return fresh
		}
	}
}

func (root *staticRoot) serveFast(req *Request, resp *Response, rel string, cache *staticFileCache) bool {
	if root.noOpenat2.Load() {
		return false
	}
	if cache != nil {
		if e := cache.fresh(rel); e != nil && cache.serveEntry(e, req, resp) {
			return true
		}
	}
	sc := staticScratchPool.Get().(*staticScratch)
	served := root.serveFastWith(sc, req, resp, rel, cache)
	staticScratchPool.Put(sc)
	return served
}

func (root *staticRoot) serveFastWith(sc *staticScratch, req *Request, resp *Response, rel string, cache *staticFileCache) bool {
	dir := root.acquireDir(sc)
	if dir == nil {
		return false
	}
	served := root.serveBeneath(sc, dir.fd, req, resp, rel, cache)
	dir.release()
	return served
}

func (root *staticRoot) serveBeneath(sc *staticScratch, dirfd int, req *Request, resp *Response, rel string, cache *staticFileCache) bool {
	if cache != nil && cache.servesWithoutOpen(rel, req) {
		fd, errno := sc.openBeneath(dirfd, rel, staticProbeOpenFlags)
		if errno != 0 {
			cache.forget(rel)
			return root.openFailed(errno, resp)
		}
		statErr := unix.Fstat(fd, &sc.st)
		_ = unix.Close(fd)
		if statErr != nil || sc.st.Mode&unix.S_IFMT != unix.S_IFREG {
			cache.forget(rel)
			return false
		}
		if e := cache.lookup(rel, &sc.st); e != nil && cache.serveEntry(e, req, resp) {
			return true
		}
	}
	fd, errno := sc.openBeneath(dirfd, rel, staticFileOpenFlags)
	if errno != 0 {
		return root.openFailed(errno, resp)
	}
	return serveStaticFD(sc, req, resp, fd, rel, cache)
}

func (root *staticRoot) openFailed(errno unix.Errno, resp *Response) bool {
	switch errno {
	case unix.ENOENT:
		resp.Status(http.StatusNotFound).String(http.StatusText(http.StatusNotFound))
		return true
	case unix.ENOSYS:
		root.noOpenat2.Store(true)
	}
	return false
}

func serveStaticFD(sc *staticScratch, req *Request, resp *Response, fd int, rel string, cache *staticFileCache) bool {
	if unix.Fstat(fd, &sc.st) != nil || sc.st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return false
	}
	if cache != nil && cache.serveFilled(sc, req, resp, fd, rel) {
		return true
	}
	fi := &statFileInfo{name: rel, st: sc.st}
	f := os.NewFile(uintptr(fd), rel)
	_ = resp.serveContent(req, f, fi, detectMIME(rel), nil)
	_ = f.Close()
	return true
}

var staticCacheClock = turbo.UnixNano

type staticFileCache struct {
	entries       *alosmap.TypedMap[string, *staticCacheEntry]
	filling       *alosmap.TypedMap[string, struct{}]
	bytes         atomic.Int64
	fds           atomic.Int64
	maxBytes      int64
	maxFileSize   int64
	ttl           int64
	compressQueue chan staticCompressJob
	variantSlots  *alosmap.TypedMap[string, *staticVariantSlot]
	compressing   atomic.Bool
	builds        atomic.Int64
}

type staticCacheEntry struct {
	id           staticFileID
	key          string
	data         []byte
	size         int64
	fd           atomic.Pointer[staticFD]
	contentType  string
	sizeText     string
	validators   contentValidators
	cost         int64
	freshUntil   atomic.Int64
	compressible bool
	slot         atomic.Pointer[staticVariantSlot]
}

func staticCacheTTLNanos(ttl time.Duration) int64 {
	switch {
	case ttl == 0:
		return int64(staticCacheDefaultTTL)
	case ttl < 0:
		return 0
	}
	return int64(ttl)
}

func newStaticFileCache(cfg StaticConfig) *staticFileCache {
	if cfg.DisableCache {
		return nil
	}
	c := &staticFileCache{
		entries:     alosmap.NewTyped[string, *staticCacheEntry](),
		filling:     alosmap.NewTyped[string, struct{}](),
		maxBytes:    cfg.CacheMaxBytes,
		maxFileSize: cfg.CacheMaxFileSize,
		ttl:         staticCacheTTLNanos(cfg.CacheTTL),
	}
	if c.maxBytes <= 0 {
		c.maxBytes = staticCacheDefaultMaxBytes
	}
	if c.maxFileSize <= 0 {
		c.maxFileSize = c.maxBytes / staticCacheDefaultFileShare
	}
	if c.maxFileSize > c.maxBytes {
		c.maxFileSize = c.maxBytes
	}
	if !cfg.DisableCompression {
		c.compressQueue = make(chan staticCompressJob, staticCompressQueueSize)
		c.variantSlots = alosmap.NewTyped[string, *staticVariantSlot]()
	}
	runtime.AddCleanup(c, releaseStaticCacheFDs, c.entries)
	return c
}

func releaseStaticCacheFDs(entries *alosmap.TypedMap[string, *staticCacheEntry]) {
	entries.Range(func(_ string, e *staticCacheEntry) bool {
		if h := e.fd.Swap(staticFDRetired); h != nil && h != staticFDRetired {
			h.release()
		}
		return true
	})
}

func (c *staticFileCache) fresh(rel string) *staticCacheEntry {
	if c.ttl == 0 {
		return nil
	}
	e, ok := c.entries.Load(rel)
	if !ok || turbo.Now() >= e.freshUntil.Load() {
		return nil
	}
	return e
}

func (c *staticFileCache) servesWithoutOpen(rel string, req *Request) bool {
	e, ok := c.entries.Load(rel)
	if !ok {
		return false
	}
	if e.sendsByFD(req) {
		h := e.fd.Load()
		return h != nil && h != staticFDRetired
	}
	return e.data != nil
}

func (c *staticFileCache) serveFilled(sc *staticScratch, req *Request, resp *Response, fd int, rel string) bool {
	byFD := sendsFilePlainH1(req)
	e := c.lookupOrFill(sc, fd, rel, !byFD)
	if e == nil {
		return false
	}
	if v := c.variantFor(e, req); v != nil {
		_ = unix.Close(fd)
		e.serveVariant(req, resp, v)
		return true
	}
	if byFD && e.sendsByFD(req) {
		if sw := staticFileWriter(resp); sw != nil {
			h := c.attachFD(e, fd)
			if h == nil {
				return false
			}
			e.serveFD(req, resp, sw, h)
			return true
		}
	}
	if !c.serveEntry(e, req, resp) {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func (c *staticFileCache) attachFD(e *staticCacheEntry, fd int) *staticFD {
	if cur := e.fd.Load(); cur != nil {
		if cur != staticFDRetired && cur.tryAcquire() {
			_ = unix.Close(fd)
			return cur
		}
		return nil
	}
	if c.fds.Add(1) > staticCacheMaxFDs {
		c.fds.Add(-1)
		return nil
	}
	h := &staticFD{fd: fd}
	h.refs.Store(staticFDEntryAndCallerRefs)
	if !e.fd.CompareAndSwap(nil, h) {
		c.fds.Add(-1)
		return nil
	}
	return h
}

func (c *staticFileCache) retire(e *staticCacheEntry) {
	c.bytes.Add(-e.cost)
	c.retireVariants(e)
	if h := e.fd.Swap(staticFDRetired); h != nil && h != staticFDRetired {
		c.fds.Add(-1)
		h.release()
	}
}

func (c *staticFileCache) renew(e *staticCacheEntry) {
	if c.ttl != 0 {
		e.freshUntil.Store(turbo.Now() + c.ttl)
	}
}

func (c *staticFileCache) lookup(rel string, st *unix.Stat_t) *staticCacheEntry {
	e, ok := c.entries.Load(rel)
	if !ok {
		return nil
	}
	if e.id != staticFileIDOf(st) {
		c.drop(e)
		return nil
	}
	c.renew(e)
	return e
}

func (c *staticFileCache) forget(rel string) {
	if e, ok := c.entries.Load(rel); ok {
		c.drop(e)
	}
}

func (c *staticFileCache) drop(e *staticCacheEntry) {
	if c.entries.CompareAndDelete(e.key, e) {
		c.retire(e)
	}
}

func (c *staticFileCache) lookupOrFill(sc *staticScratch, fd int, rel string, fillData bool) *staticCacheEntry {
	if e := c.lookup(rel, &sc.st); e != nil && (e.data != nil || !fillData) {
		return e
	}
	id := staticFileIDOf(&sc.st)
	if !id.settled(staticCacheClock()) {
		return nil
	}
	switch {
	case !fillData && id.size > staticCacheEvictingFileSize:
		return c.fillFDOnly(sc, rel)
	case id.size > c.maxFileSize:
		return nil
	case id.size > staticCacheEvictingFileSize:
		return c.fillLarge(sc, fd, rel, id)
	}
	data, ok := preadFull(fd, id.size)
	if !ok || unix.Fstat(fd, &sc.st) != nil || staticFileIDOf(&sc.st) != id {
		return nil
	}
	e := c.newEntry(rel, data, &sc.st)
	c.renew(e)
	if c.reserve(e.cost) {
		c.publish(e)
	}
	return e
}

func (c *staticFileCache) publish(e *staticCacheEntry) {
	e.fd.Store(nil)
	if old, loaded := c.entries.Swap(e.key, e); loaded {
		c.retire(old)
	}
}

func (c *staticFileCache) fillFDOnly(sc *staticScratch, rel string) *staticCacheEntry {
	e := c.newEntry(rel, nil, &sc.st)
	c.renew(e)
	if !c.reserveFree(e.cost) {
		return nil
	}
	c.publish(e)
	return e
}

func (c *staticFileCache) fillLarge(sc *staticScratch, fd int, rel string, id staticFileID) *staticCacheEntry {
	cost := staticCacheEntryCost(rel, id.size)
	if _, busy := c.filling.LoadOrStore(rel, struct{}{}); busy {
		return nil
	}
	defer c.filling.Delete(rel)
	if !c.reserveFree(cost) {
		return nil
	}
	data, ok := preadFull(fd, id.size)
	if !ok || unix.Fstat(fd, &sc.st) != nil || staticFileIDOf(&sc.st) != id {
		c.bytes.Add(-cost)
		return nil
	}
	e := c.newEntry(rel, data, &sc.st)
	c.renew(e)
	c.publish(e)
	return e
}

func staticCacheEntryCost(rel string, size int64) int64 {
	return size + int64(len(rel)) + staticCacheEntryOverhead
}

func preadFull(fd int, size int64) ([]byte, bool) {
	data := make([]byte, size)
	if size == 0 {
		return data, true
	}
	iov := [1]unix.Iovec{{Base: &data[0]}}
	iov[0].SetLen(len(data))
	if _, err := preadvAll(fd, iov[:], 0, 0); err != nil {
		return nil, false
	}
	return data, true
}

func (c *staticFileCache) newEntry(rel string, data []byte, st *unix.Stat_t) *staticCacheEntry {
	e := newStaticCacheEntry(rel, data, st)
	e.compressible = c.compressible(e)
	return e
}

func newStaticCacheEntry(rel string, data []byte, st *unix.Stat_t) *staticCacheEntry {
	fi := statFileInfo{name: rel, st: *st}
	e := &staticCacheEntry{
		id:          staticFileIDOf(st),
		key:         strings.Clone(rel),
		data:        data,
		size:        st.Size,
		contentType: detectMIME(rel),
		sizeText:    strconv.FormatInt(st.Size, 10),
		validators:  fileValidators(&fi),
		cost:        staticCacheEntryCost(rel, int64(len(data))),
	}
	e.fd.Store(staticFDRetired)
	return e
}

func (c *staticFileCache) reserve(cost int64) bool {
	if cost > c.maxBytes {
		return false
	}
	for c.bytes.Add(cost) > c.maxBytes {
		c.bytes.Add(-cost)
		if !c.evict(cost) {
			return false
		}
	}
	return true
}

func (c *staticFileCache) reserveFree(cost int64) bool {
	if c.bytes.Add(cost) > c.maxBytes {
		c.bytes.Add(-cost)
		return false
	}
	return true
}

func (c *staticFileCache) evict(need int64) bool {
	var freed int64
	c.entries.Range(func(key string, e *staticCacheEntry) bool {
		if c.entries.CompareAndDelete(key, e) {
			c.retire(e)
			freed += e.cost
		}
		return freed < need
	})
	return freed > 0
}

func (e *staticCacheEntry) sendsByFD(req *Request) bool {
	return e.size >= staticFDSendMin && req.Method == http.MethodGet && sendsFilePlainH1(req)
}

func (c *staticFileCache) serveEntry(e *staticCacheEntry, req *Request, resp *Response) bool {
	if v := c.variantFor(e, req); v != nil {
		e.serveVariant(req, resp, v)
		return true
	}
	if e.sendsByFD(req) {
		if sw := staticFileWriter(resp); sw != nil {
			if h := e.fd.Load(); h != nil && h != staticFDRetired && h.tryAcquire() {
				e.serveFD(req, resp, sw, h)
				return true
			}
		}
	}
	if e.data != nil {
		e.serve(req, resp)
		return true
	}
	if req.Method != http.MethodHead {
		return false
	}
	sw := staticFileWriter(resp)
	if sw == nil {
		return false
	}
	if _, ok := e.writeFDHeaders(req, resp, sw); ok {
		_ = sw.Close()
	}
	return true
}

type staticServePlan struct {
	status       int
	start        int64
	length       int64
	contentRange string
}

func (e *staticCacheEntry) plan(req *Request, resp *Response, v *contentValidators) (staticServePlan, bool) {
	switch evaluatePreconditions(req, v) {
	case preconditionNotModified:
		resp.SetHeader("ETag", v.etag).SetHeader("Last-Modified", v.lastModified).Status(http.StatusNotModified)
		e.addVary(resp)
		return staticServePlan{}, false
	case preconditionFailed:
		resp.Status(http.StatusPreconditionFailed).String("Precondition Failed")
		return staticServePlan{}, false
	}
	p := staticServePlan{status: http.StatusOK, length: e.size}
	if spec := req.Header("Range"); spec != "" && req.Method == http.MethodGet && ifRangeAllows(req, v) {
		start, length, outcome := parseByteRange(spec, e.size)
		switch outcome {
		case rangeUnsatisfiable:
			resp.SetHeader("Content-Range", unsatisfiablePrefix+e.sizeText).Status(http.StatusRequestedRangeNotSatisfiable).String("Range Not Satisfiable")
			return staticServePlan{}, false
		case rangeSatisfiable:
			p = staticServePlan{status: http.StatusPartialContent, start: start, length: length, contentRange: formatContentRange(start, length, e.size)}
		}
	}
	resp.Headers = append(resp.Headers, [2]string{"accept-ranges", byteRangeUnit}, [2]string{"etag", v.etag}, [2]string{"last-modified", v.lastModified})
	e.addVary(resp)
	if p.contentRange != "" {
		resp.Headers = append(resp.Headers, [2]string{"content-range", p.contentRange})
	}
	return p, true
}

func (e *staticCacheEntry) serve(req *Request, resp *Response) {
	p, ok := e.plan(req, resp, &e.validators)
	if !ok {
		return
	}
	resp.StatusCode = p.status
	resp.setBodyNoCopy(e.data[p.start:p.start+p.length], e.contentType)
	resp.fileBody = true
}

func staticFileWriter(resp *Response) *epollH1StreamWriter {
	return h1StreamWriterOf(resp.ensureSW())
}

func (e *staticCacheEntry) serveFD(req *Request, resp *Response, sw *epollH1StreamWriter, h *staticFD) {
	p, ok := e.writeFDHeaders(req, resp, sw)
	if !ok {
		h.release()
		return
	}
	sw.sendFileDetached(h, p.start, p.length)
	_ = sw.Close()
}

func (e *staticCacheEntry) writeFDHeaders(req *Request, resp *Response, sw *epollH1StreamWriter) (staticServePlan, bool) {
	p, ok := e.plan(req, resp, &e.validators)
	if !ok {
		return p, false
	}
	lengthText := e.sizeText
	if p.length != e.size {
		lengthText = strconv.FormatInt(p.length, 10)
	}
	resp.Headers = append(resp.Headers, [2]string{"content-length", lengthText})
	if err := sw.WriteHeader(p.status, resp.Headers, e.contentType); err != nil {
		return p, false
	}
	resp.SetStreamer(resp.ensureSW())
	return p, true
}

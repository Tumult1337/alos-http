//go:build linux && amd64

package core

import (
	"crypto/x509"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	epollConnSlabSize       = 128
	epollEventBatch         = 512
	epollListenBacklog      = 4096
	epollShrinkSlackSlabs   = 3
	epollBufShrinkThreshold = 32 << 10
)

const (
	epollActionNeedRead = iota
	epollActionCloseAfterFlush
	// epollActionProxyInFlight means an upstream exchange owns this connection
	// until it completes: nothing may flush, recycle or close it meanwhile.
	epollActionProxyInFlight
	// epollActionDetached means a handler took the socket over on the event
	// loop thread; the connection object goes back to the pool.
	epollActionDetached
)

type epollConn struct {
	fd          int
	generation  uint32
	protocol    uint8
	closeAfter  bool
	outArmed    bool
	tls         bool
	tlsVersion  uint16
	dispatching bool
	readPending bool
	peerHup     bool
	inputEOF    bool
	flushQueued bool
	ipHeld      bool
	inFlight    int
	readN       int
	writeSent   int
	h1Off       int
	deadline    int64
	readBuf     []byte
	writeBuf    []byte
	remoteAddr  string
	ipKey       string
	req         Request
	h1Cancel    cancelSlot
	resp        Response
	h2          tlsWorkerH2State
	slab        *epollSlab

	h2Streaming     map[uint32]*epollH2StreamWriter
	h2Draining      int
	h2EndedInFlight int
	h2PumpDue       bool
	inTLSFrameDrain bool
	h2BodyIn        map[uint32]*h2BodyIn

	h1DispatchGen   uint32
	h1ContinueSent  bool
	h1DispatchClose bool
	h1DispatchFast  bool
	h1AsyncFn       func()
	h1DoneNext      *epollConn
	h1Body          []byte
	h1BodyOff       int
	h1Stream        *epollH1StreamWriter
	h1OutKeepAlive  bool
	h1OutComplete   bool
	h1ResumeDue     bool
	h1In            *h1BodyIn
	lingering       bool
	lingerLeft      int

	phase        uint8
	selectedALPN string
	hsReader     *TrafficAEAD
	appReader    *TrafficAEAD
	appWriter    *TrafficAEAD
	plainBuf     []byte
	appBuf       []byte
	appBufOff    int
	clientHello  *ParsedClientHello
	expectedFin  [64]byte
	expectedFinN int
	tls12        *tls12State
	tlsRetry     *tls13Retry
	ticket       *pendingTicket
	clientAuth   *tls13ClientAuth
	tlsAlertSent bool
	peerCerts    []*x509.Certificate
	tlsCertEntry *CertEntry

	tlsPeerClosed     bool
	tlsUselessRecords uint8
	cipherOff         int

	reqBodyCopy     []byte
	h1BodyAccounted int64
	h1BodyDeadline  int64
	chunkScanPos    int
	h2GoingAway     bool

	h1AttacherFn     func(*Request) net.Conn
	h1AttacherGen    uint32
	h1AttacherInline bool
	takeoverPinned   bool
	takeoverParked   bool
	unpinNext        *epollConn
	connLimiter      *ConnectionLimiter

	// proxyEx is the in-flight upstream exchange for this connection, and
	// pausedBackend the backend socket whose reads were disarmed because this
	// client fell behind while a response was being relayed.
	proxyEx       *proxyExchange
	pausedBackend *backendConn
	tunnelBE      *backendConn

	h2ProxyBuffered int64
	tunnelPaused    bool

	worker *epollWorker
}

type epollSlab struct {
	conns []epollConn
	free  int
}

type epollConnPool struct {
	slabs      []*epollSlab
	free       []*epollConn
	floorSlabs int
	batchSize  int
	parked     int
	server     *Server
}

func (p *epollConnPool) slabSize() int {
	if p.batchSize > 0 {
		return p.batchSize
	}
	return epollConnSlabSize
}

func (p *epollConnPool) addSlab() {
	bs := p.slabSize()
	s := &epollSlab{conns: make([]epollConn, bs), free: bs}
	for i := range s.conns {
		c := &s.conns[i]
		c.slab = s
		p.free = append(p.free, c)
	}
	p.slabs = append(p.slabs, s)
}

func (p *epollConnPool) prewarm(minConns int) {
	bs := p.slabSize()
	need := (minConns + bs - 1) / bs
	if need < 1 {
		need = 1
	}
	p.floorSlabs = need
	for len(p.slabs) < need {
		p.addSlab()
	}
	for i := 0; i < minConns; i++ {
		releaseEpollReadBuf(make([]byte, epollReadBufCap))
	}
}

func (p *epollConnPool) get() *epollConn {
	if len(p.free) == 0 {
		p.addSlab()
	}
	c := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	c.slab.free--
	return c
}

func (p *epollConnPool) slotsHeld() int {
	return len(p.slabs)*p.slabSize() - len(p.free) - p.parked
}

func shrinkEpollBuf(b []byte) []byte {
	if cap(b) > epollBufShrinkThreshold {
		return nil
	}
	return b[:0]
}

func (c *epollConn) releaseClientHello() {
	if c.clientHello != nil {
		c.clientHello.Reset()
		clientHelloPool.Put(c.clientHello)
		c.clientHello = nil
	}
}

func (p *epollConnPool) put(c *epollConn) {
	p.releaseConnSlot()
	p.recycle(c)
}

func (p *epollConnPool) releaseConnSlot() {
	if p.server != nil {
		p.server.releaseTrackedConn()
		Stats.ActiveConns.Add(-1)
	}
}

func (p *epollConnPool) recycle(c *epollConn) {
	if c.ipHeld {
		if p.server != nil {
			p.server.perIPConnLimiter.Load().release(c.ipKey)
		}
		c.ipHeld = false
		c.ipKey = ""
	}
	releaseEpollReadBuf(c.readBuf)
	c.readBuf = nil
	releaseIOBuf(c.writeBuf)
	c.writeBuf = nil
	releaseIOBuf(c.appBuf)
	c.appBuf = nil
	releaseIOBuf(c.plainBuf)
	c.plainBuf = nil
	c.reqBodyCopy = shrinkEpollBuf(c.reqBodyCopy)
	c.releaseH1BodyBudget()
	c.req.Body = nil
	c.resp.resetFastH1()
	if c.h2.decoder != nil {
		HpackDecoderPool.Put(c.h2.decoder)
		c.h2.decoder = nil
	}
	c.releaseClientHello()
	c.deadline = 0
	p.free = append(p.free, c)
	c.slab.free++
	if len(p.slabs) > p.floorSlabs && len(p.free) >= p.slabSize()*epollShrinkSlackSlabs {
		p.shrinkOne()
	}
}

func (c *epollConn) reserveH1BodyBudget(srv *Server, n int) bool {
	if n <= 0 || c.h1BodyAccounted > 0 {
		return true
	}
	if !srv.tryReserveBodyBytes(n) {
		return false
	}
	c.h1BodyAccounted = int64(n)
	return true
}

func (c *epollConn) releaseH1BodyBudget() {
	if c.h1BodyAccounted <= 0 {
		return
	}
	if c.worker != nil && c.worker.server != nil {
		c.worker.server.releaseBodyBytes(c.h1BodyAccounted)
	}
	c.h1BodyAccounted = 0
}

func h1ChunkedBodyReservation(srv *Server) int {
	limit := srv.effectiveReadCap()
	if maxBody := srv.limits.Load().MaxBodySize; maxBody > 0 && (limit == readCapUnlimited || maxBody < int64(limit)) {
		limit = int(maxBody)
	}
	return limit
}

func (p *epollConnPool) shrinkOne() {
	bs := p.slabSize()
	victim := -1
	for i := len(p.slabs) - 1; i >= 0; i-- {
		if p.slabs[i].free == bs {
			victim = i
			break
		}
	}
	if victim < 0 {
		return
	}
	vs := p.slabs[victim]
	filtered := p.free[:0]
	for _, c := range p.free {
		if c.slab != vs {
			filtered = append(filtered, c)
		}
	}
	for i := len(filtered); i < len(p.free); i++ {
		p.free[i] = nil
	}
	p.free = filtered
	p.slabs = append(p.slabs[:victim], p.slabs[victim+1:]...)
}

type epollWorker struct {
	server          *Server
	bytesIn         uint64
	bytesOut        uint64
	epfd            int
	listenerFD      int
	wakeFd          int
	coreID          int
	spawned         int
	tlsMode         bool
	conns           []*epollConn
	pool            epollConnPool
	events          []unix.EpollEvent
	taskCh          chan func(*epollWorker)
	handlers        *handlerPool
	taskPending     atomic.Bool
	h1Done          atomic.Pointer[epollConn]
	takeoverUnpins  atomic.Pointer[epollConn]
	parked          atomic.Bool
	wakeBuf         [8]byte
	flushList       []*epollConn
	h2FinishScratch []byte
	readTO          int64
	headerTO        int64
	handshakeTO     int64
	writeTO         int64
	idleTO          int64
	maxHeaderSize   int
	maxBodySize     int64
	streamBodyAbove int64
	limitsGen       uint64
	discardBuf      []byte
	maxPendingWrite int
	lastSweep       int64
	acceptResumeAt  int64
	acceptBackoff   time.Duration
	draining        bool
	drainExpired    bool
	be              beLoop
	beCfg           fpConfig
	exFree          *Exchange
	pxFree          *proxyExchange
	beScratch       []byte
	hdrStrings      [][2]string
}

// ListenAndServeEpollH2 listens on addr and serves plain HTTP/1.1 and
// HTTP/2-via-prior-knowledge connections using the epoll backend, blocking
// until an error occurs.
func (s *Server) ListenAndServeEpollH2(addr string) error {
	return s.serveEpoll(addr, false)
}

// ListenAndServeEpollTLS listens on addr and serves TLS-terminated HTTP/1.1
// and HTTP/2 connections using the epoll backend, blocking until an error
// occurs.
func (s *Server) ListenAndServeEpollTLS(addr string) error {
	return s.serveEpoll(addr, true)
}

func (s *Server) epollListenerCount() int {
	if s.config.Listeners > 0 {
		return s.config.Listeners
	}
	return autoWorkerCount()
}

func (s *Server) serveEpoll(addr string, tlsMode bool) error {
	workers, err := s.prepareEpollWorkers(addr, tlsMode)
	if err != nil {
		if err == ErrServerShutdown {
			return nil
		}
		return err
	}
	results, err := s.startEpollWorkers(workers)
	if err != nil {
		if err == ErrServerShutdown {
			return nil
		}
		return err
	}
	return <-results
}

func (s *Server) prepareEpollWorkers(addr string, tlsMode bool) ([]*epollWorker, error) {
	s.adoptAssignedEngines()
	s.Router.Build()
	s.computeFastDispatch()
	workerCount := s.epollListenerCount()
	minPerWorker := 0
	if s.config.MinPrealloc > 0 {
		minPerWorker = (s.config.MinPrealloc + workerCount - 1) / workerCount
	}
	workers := make([]*epollWorker, 0, workerCount)
	for i := 0; i < workerCount; i++ {
		if s.shuttingDown.Load() {
			closeUnstartedEpollWorkers(workers)
			return nil, ErrServerShutdown
		}
		listenerFD, err := epollBind(addr)
		if err != nil {
			closeUnstartedEpollWorkers(workers)
			return nil, fmt.Errorf("epoll bind %s: %w", addr, err)
		}
		worker, err := newEpollWorkerFromFD(s, listenerFD, minPerWorker)
		if err != nil {
			closeUnstartedEpollWorkers(workers)
			return nil, err
		}
		worker.coreID = i % runtime.NumCPU()
		worker.tlsMode = tlsMode
		workers = append(workers, worker)
	}
	if s.shuttingDown.Load() {
		closeUnstartedEpollWorkers(workers)
		return nil, ErrServerShutdown
	}
	return workers, nil
}

func closeUnstartedEpollWorkers(workers []*epollWorker) {
	for _, worker := range workers {
		worker.server.removeShutdownWaker(worker)
		for _, fd := range []int{worker.listenerFD, worker.epfd, worker.wakeFd} {
			if err := unix.Close(fd); err != nil {
				worker.server.logger().Warn("epoll startup descriptor close failed", "err", err)
			}
		}
		worker.handlers.close()
	}
}

func (s *Server) startEpollWorkers(workers []*epollWorker) (<-chan error, error) {
	for _, worker := range workers {
		if s.shuttingDown.Load() {
			closeUnstartedEpollWorkers(workers)
			return nil, ErrServerShutdown
		}
		if err := unix.Listen(worker.listenerFD, epollListenBacklog); err != nil {
			closeUnstartedEpollWorkers(workers)
			return nil, fmt.Errorf("epoll listen worker %d: %w", worker.coreID, err)
		}
	}
	if s.shuttingDown.Load() {
		closeUnstartedEpollWorkers(workers)
		return nil, ErrServerShutdown
	}
	go s.epollScavenger()
	errCh := make(chan error, len(workers))
	for _, worker := range workers {
		go func() { errCh <- worker.run() }()
	}
	return errCh, nil
}

func (s *Server) epollScavenger() {
	const (
		freeThrottleNs  = 10 * int64(time.Second)
		idleRatePerTick = 40
		connActive      = 32
		minReturnable   = 24 << 20
		maxReclaims     = 2
	)
	var lastFree int64
	var lastReqs, rate uint64
	var armed bool
	var reclaims int
	var ms runtime.MemStats
	for {
		select {
		case <-s.done:
			return
		default:
		}
		turbo.Sleep(2 * time.Second)
		now := turbo.UnixNano()
		cur := s.activeConns.Load()
		reqs := Stats.TotalReqs.Load()
		if reqs >= lastReqs {
			rate = reqs - lastReqs
		} else {
			rate = 0
		}
		lastReqs = reqs

		if rate > idleRatePerTick || cur > connActive {
			armed = true
			reclaims = 0
			continue
		}
		if !armed || reclaims >= maxReclaims {
			continue
		}
		if now-lastFree < freeThrottleNs {
			continue
		}
		runtime.ReadMemStats(&ms)
		heldIdle := int64(ms.HeapIdle) - int64(ms.HeapReleased)
		if heldIdle <= minReturnable && ms.HeapInuse <= minReturnable {
			armed = false
			continue
		}
		debug.FreeOSMemory()
		lastFree = now
		reclaims++
		if reclaims >= maxReclaims {
			armed = false
		}
	}
}

func newEpollWorker(s *Server, addr string, minPrealloc int) (*epollWorker, error) {
	listenerFD, err := epollListen(addr)
	if err != nil {
		return nil, fmt.Errorf("epoll listen %s: %w", addr, err)
	}
	return newEpollWorkerFromFD(s, listenerFD, minPrealloc)
}

func newEpollWorkerFromFD(s *Server, lfd int, minPrealloc int) (*epollWorker, error) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		_ = unix.Close(lfd)
		return nil, fmt.Errorf("epoll create: %w", err)
	}
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(lfd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, lfd, &ev); err != nil {
		_ = unix.Close(lfd)
		_ = unix.Close(epfd)
		return nil, fmt.Errorf("epoll add listener: %w", err)
	}
	wfd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		_ = unix.Close(lfd)
		_ = unix.Close(epfd)
		return nil, fmt.Errorf("eventfd: %w", err)
	}
	wev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(wfd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, wfd, &wev); err != nil {
		_ = unix.Close(lfd)
		_ = unix.Close(epfd)
		_ = unix.Close(wfd)
		return nil, fmt.Errorf("epoll add wake: %w", err)
	}
	w := &epollWorker{
		server:     s,
		epfd:       epfd,
		listenerFD: lfd,
		wakeFd:     wfd,
		conns:      make([]*epollConn, 1024),
		events:     make([]unix.EpollEvent, epollEventBatch),
		taskCh:     make(chan func(*epollWorker), epollTaskQueueSize),
		handlers:   newHandlerPool(handlerPoolWorkersPerLoop),
		flushList:  make([]*epollConn, 0, 64),
	}
	w.pool.server = s
	w.pool.batchSize = s.preallocBatch()
	w.refreshLimits()
	w.maxPendingWrite = epollMaxPendingWriteDefault
	if s.config.MaxPendingWriteBytes > 0 {
		w.maxPendingWrite = int(s.config.MaxPendingWriteBytes)
	}
	w.pool.prewarm(minPrealloc)
	w.initBackendLoop()
	s.addShutdownWaker(w)
	return w, nil
}

func (w *epollWorker) wakeForShutdown() {
	var one uint64 = 1
	_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
}

func (c *epollConn) cancelH1(cause error) {
	if s := c.req.cancelSrc; s != nil {
		s.cancel(cause)
	}
}

func (c *epollConn) cancelInFlight(cause error) {
	c.cancelH1(cause)
	c.h2.cancelBusy(cause)
}

func (w *epollWorker) cancelInFlight(cause error) {
	w.postTask(func(w *epollWorker) {
		w.drainExpired = true
		for _, c := range w.conns {
			if c != nil && c.fd >= 0 {
				c.cancelInFlight(cause)
			}
		}
	})
}

func (s *Server) preallocBatch() int {
	if s.config.PreallocBatch > 0 {
		return s.config.PreallocBatch
	}
	return epollConnSlabSize
}

const epollTaskQueueSize = 8192

func (w *epollWorker) postTask(fn func(*epollWorker)) {
	w.taskCh <- fn
	w.taskPending.Store(true)
	if w.parked.Load() {
		var one uint64 = 1
		_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
	}
}

func (w *epollWorker) pushH1Done(c *epollConn) {
	for {
		head := w.h1Done.Load()
		c.h1DoneNext = head
		if w.h1Done.CompareAndSwap(head, c) {
			break
		}
	}
	w.taskPending.Store(true)
	if w.parked.Load() {
		var one uint64 = 1
		_, _ = unix.Write(w.wakeFd, (*[8]byte)(unsafe.Pointer(&one))[:])
	}
}

func (w *epollWorker) drainTasks() {
	w.taskPending.Store(false)
	done := w.h1Done.Swap(nil)
	for {
		select {
		case fn := <-w.taskCh:
			w.runTask(fn)
		default:
			w.finishH1Done(done)
			if w.takeoverUnpins.Load() != nil {
				w.runTakeoverUnpins()
			}
			return
		}
	}
}

func (w *epollWorker) finishH1Done(head *epollConn) {
	var ordered *epollConn
	for c := head; c != nil; {
		next := c.h1DoneNext
		c.h1DoneNext = ordered
		ordered = c
		c = next
	}
	for ordered != nil {
		c := ordered
		ordered = c.h1DoneNext
		c.h1DoneNext = nil
		w.runH1Finish(c)
	}
}

func (w *epollWorker) runH1Finish(c *epollConn) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(nil, r)
		}
	}()
	c.finishH1Dispatch(w, c.h1DispatchGen, c.h1DispatchClose)
}

func (w *epollWorker) runTask(fn func(*epollWorker)) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(nil, r)
		}
	}()
	fn(w)
}

func (w *epollWorker) serviceConn(c *epollConn, evs uint32) {
	defer func() {
		if r := recover(); r != nil {
			w.server.reportPanic(nil, r)
			w.closeConn(c)
		}
	}()
	if evs&(unix.EPOLLERR|unix.EPOLLHUP) != 0 && evs&unix.EPOLLIN == 0 {
		w.closeConn(c)
		return
	}
	if evs&unix.EPOLLOUT != 0 {
		if !w.flush(c) {
			return
		}
	}
	if evs&(unix.EPOLLIN|unix.EPOLLRDHUP) != 0 {
		w.readable(c, evs&unix.EPOLLRDHUP != 0)
	}
}

func epollBind(addr string) (int, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	sa := &unix.SockaddrInet4{Port: tcpAddr.Port}
	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		copy(sa.Addr[:], ip4)
	}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func epollListen(addr string) (int, error) {
	fd, err := epollBind(addr)
	if err != nil {
		return -1, err
	}
	if err := unix.Listen(fd, epollListenBacklog); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (w *epollWorker) run() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer unix.Close(w.epfd)
	defer unix.Close(w.wakeFd)
	defer w.server.removeShutdownWaker(w)
	defer w.handlers.close()
	accepting := true
	for {
		if accepting {
			select {
			case <-w.server.done:
				_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, w.listenerFD, nil)
				_ = unix.Close(w.listenerFD)
				w.listenerFD = -1
				accepting = false
				w.draining = true
			default:
			}
		}
		w.flushByteCounters()
		if !accepting {
			w.drainForShutdown()
			if !w.hasClientConns() && w.pool.slotsHeld() == 0 {
				return nil
			}
		}
		w.be.seq++
		n, err := w.waitEvents()
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("epoll wait: %w", err)
		}
		w.refreshLimits()
		acceptPending := false
		tasksPending := false
		for i := 0; i < n; i++ {
			fd := int(w.events[i].Fd)
			if fd == w.listenerFD {
				acceptPending = true
				continue
			}
			if fd == w.wakeFd {
				tasksPending = true
				continue
			}
			if w.events[i].Pad == epollFDClassBackend {
				w.backendEvent(fd, w.events[i].Events)
				continue
			}
			if fd < 0 || fd >= len(w.conns) {
				continue
			}
			c := w.conns[fd]
			if c == nil {
				continue
			}
			w.serviceConn(c, w.events[i].Events)
		}
		if tasksPending {
			_, _ = unix.Read(w.wakeFd, w.wakeBuf[:])
		}
		for round := 0; round < epollDispatchRounds && (tasksPending || w.spawned > 0 || w.taskPending.Load()); round++ {
			tasksPending = false
			if w.spawned > 0 {
				w.spawned = 0
				w.yieldToHandlers()
			}
			if w.taskPending.Load() {
				w.drainTasks()
			}
		}
		if len(w.flushList) > 0 {
			w.flushPending()
		}
		if w.acceptResumeAt != 0 && w.resumeAcceptIfDue(turbo.UnixNano()) {
			acceptPending = true
		}
		if acceptPending {
			w.acceptLoop()
		}
		w.sweepDeadlines()
	}
}

// waitEvents blocks for readiness. The parked flag lets postTask skip the
// eventfd wake whenever the worker is not actually inside epoll_wait.
func (w *epollWorker) waitEvents() (int, error) {
	waitMs := epollSweepIntervalMs
	if w.be.liveConns > 0 {
		waitMs = min(waitMs, w.be.nextTimeoutMs())
	}
	if w.acceptResumeAt != 0 {
		waitMs = min(waitMs, w.msUntilAcceptResume(turbo.UnixNano()))
	}
	if w.draining {
		waitMs = min(waitMs, epollDrainPollMs)
	}
	w.parked.Store(true)
	if w.taskPending.Load() {
		waitMs = 0
	}
	n, err := unix.EpollWait(w.epfd, w.events, waitMs)
	w.parked.Store(false)
	return n, err
}

func (c *epollConn) speaksH2() bool {
	return c.protocol == plainConnProtoH2 || c.phase == tlsConnPhaseH2Native
}

func (c *epollConn) unparsedInput() bool {
	if c.tls {
		return c.readN != 0 || c.appBufOff < len(c.appBuf) || (c.speaksH2() && c.h2.appBufOff < len(c.appBuf))
	}
	if c.speaksH2() {
		return c.readN != c.h2.appBufOff
	}
	return c.readN != 0
}

func (c *epollConn) bufferedInput() int {
	switch {
	case c.tls:
		return c.readN
	case c.speaksH2():
		return c.readN - c.h2.appBufOff
	default:
		return c.readN - c.h1Off
	}
}

func (c *epollConn) idle() bool {
	return c.fd >= 0 && c.inFlight == 0 && !c.dispatching && c.proxyEx == nil && c.tunnelBE == nil &&
		!c.unparsedInput() && !c.outArmed && c.writeSent == len(c.writeBuf) &&
		len(c.h2.streams) == 0 && len(c.h2.sending) == 0
}

func (w *epollWorker) drainForShutdown() {
	now := turbo.UnixNano()
	for _, c := range w.conns {
		if c == nil || c.fd < 0 {
			continue
		}
		switch {
		case c.lingering:
			c.deadline = min(c.deadline, now+int64(epollShutdownLingerTimeout))
			if w.drainExpired || now > c.deadline {
				w.closeConn(c)
			}
		case w.drainExpired && !c.runsHandler():
			w.closeConn(c)
		case c.speaksH2():
			w.goAwayForShutdown(c)
		case c.idle():
			w.closeAfterResponse(c)
		}
	}
}

func (c *epollConn) runsHandler() bool {
	return c.inFlight > 0 || c.dispatching
}

func (w *epollWorker) goAwayForShutdown(c *epollConn) {
	idle := c.idle()
	if c.h2GoingAway && !idle {
		return
	}
	if !c.h2GoingAway {
		c.h2GoingAway = true
		var goAway [h2FrameHeaderSize + 8]byte
		w.clientAppend(c, appendH2GoAwayFrame(goAway[:0], c.h2.lastStreamID, H2ErrNoError))
	}
	if idle {
		c.closeAfter = true
	}
	w.flush(c)
}

func (c *epollConn) refuseH2StreamGoingAway(streamID uint32, headerBlock []byte) bool {
	st := &c.h2
	headers, _, _, err := st.decoder.DecodeRequest(st.headersBuf[:0], headerBlock)
	st.headersBuf = headers[:0]
	if err != nil && err != errH2MalformedRequest && err != errH2HeaderListTooLarge {
		c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrCompression)
		return true
	}
	c.writeBuf = appendH2RSTStreamFrame(c.writeBuf, streamID, H2ErrRefusedStream)
	return false
}

func (w *epollWorker) hasClientConns() bool {
	for _, c := range w.conns {
		if c != nil && c.fd >= 0 {
			return true
		}
	}
	return false
}

const (
	epollSweepIntervalMs = 1000
	epollDispatchRounds  = 64
)

func (w *epollWorker) flushByteCounters() {
	if w.bytesIn != 0 {
		Stats.BytesIn.Add(w.bytesIn)
		w.bytesIn = 0
	}
	if w.bytesOut != 0 {
		Stats.BytesOut.Add(w.bytesOut)
		w.bytesOut = 0
	}
}

func (w *epollWorker) refreshLimits() {
	gen := w.server.limitsGen.Load()
	if gen == w.limitsGen && w.maxHeaderSize != 0 {
		return
	}
	l := w.server.limits.Load()
	w.readTO = int64(l.ReadTimeout)
	w.headerTO = int64(l.headerTimeout())
	w.handshakeTO = int64(l.handshakeTimeout())
	w.writeTO = int64(l.WriteTimeout)
	w.idleTO = int64(l.IdleTimeout)
	w.maxHeaderSize = l.MaxHeaderSize
	w.maxBodySize = l.MaxBodySize
	w.streamBodyAbove = l.StreamBodyAbove
	w.limitsGen = gen
}

func (w *epollWorker) bodyTooLarge(n int64) bool {
	return w.maxBodySize > 0 && n > w.maxBodySize
}

func (w *epollWorker) sweepDeadlines() {
	if w.readTO == 0 && w.writeTO == 0 && w.idleTO == 0 && w.be.liveConns == 0 {
		return
	}
	now := turbo.UnixNano()
	w.be.maybeSweep(now)
	if w.readTO == 0 && w.writeTO == 0 && w.idleTO == 0 {
		return
	}
	if now-w.lastSweep < int64(epollSweepIntervalMs)*1_000_000 {
		return
	}
	w.lastSweep = now
	for fd := 0; fd < len(w.conns); fd++ {
		c := w.conns[fd]
		if c == nil || c.fd < 0 {
			continue
		}
		if c.deadline != 0 && now > c.deadline {
			w.closeConn(c)
		}
	}
}

func deadlineFrom(to int64) int64 {
	if to <= 0 {
		return 0
	}
	return turbo.UnixNano() + to
}

func (w *epollWorker) nextReadTimeout(c *epollConn) int64 {
	if c.tls && c.phase != tlsConnPhaseApplication && c.phase != tlsConnPhaseH2Native {
		return w.handshakeTO
	}
	if c.h1BodyAccounted > 0 || c.protocol == plainConnProtoH2 || c.phase == tlsConnPhaseH2Native {
		return w.readTO
	}
	return w.headerTO
}

func (w *epollWorker) yieldToHandlers() {
	runtime.UnlockOSThread()
	runtime.Gosched()
	runtime.LockOSThread()
}

func (w *epollWorker) markFlush(c *epollConn) {
	if c.flushQueued {
		return
	}
	c.flushQueued = true
	w.flushList = append(w.flushList, c)
}

func (w *epollWorker) flushPending() {
	for i := 0; i < len(w.flushList); i++ {
		c := w.flushList[i]
		w.flushList[i] = nil
		c.flushQueued = false
		if c.fd < 0 {
			continue
		}
		if c.h2PumpDue {
			c.h2PumpDue = false
			c.h2PumpAll(w)
		}
		if !w.flush(c) {
			continue
		}
		if c.h1ResumeDue {
			c.h1ResumeDue = false
			w.resumeConn(c)
		}
	}
	w.flushList = w.flushList[:0]
}

func (w *epollWorker) acceptLoop() {
	for {
		if w.server.shuttingDown.Load() {
			return
		}
		nfd, sa, err := unix.Accept4(w.listenerFD, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			if acceptResourceExhausted(err) {
				w.pauseAccept(turbo.UnixNano())
			}
			return
		}
		w.acceptBackoff = 0
		active := w.server.activeConns.Add(1)
		Stats.ActiveConns.Add(1)
		limits := w.server.limits.Load()
		if lim := limits.MaxConns; lim > 0 && active > lim {
			w.server.releaseTrackedConn()
			Stats.ActiveConns.Add(-1)
			_ = unix.Close(nfd)
			continue
		}
		Stats.TotalConns.Add(1)
		_ = unix.SetsockoptInt(nfd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		_ = unix.SetsockoptInt(nfd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, 8192)
		c := w.pool.get()
		c.req.resetConnIdentity()
		c.fd = nfd
		c.worker = w
		c.protocol = plainConnProtoUnknown
		c.closeAfter = false
		c.outArmed = false
		c.dispatching = false
		c.readPending = false
		c.peerHup = false
		c.inputEOF = false
		c.flushQueued = false
		c.h1ContinueSent = false
		c.readN = 0
		c.writeSent = 0
		c.h1Off = 0
		c.chunkScanPos = 0
		c.h1BodyDeadline = 0
		c.h2GoingAway = false
		if w.tlsMode {
			c.deadline = deadlineFrom(w.handshakeTO)
		} else {
			c.deadline = deadlineFrom(w.headerTO)
		}
		c.remoteAddr = epollRemoteAddr(sa)
		c.connLimiter = w.server.newConnLimiter()
		c.ipHeld = false
		c.ipKey = ""
		if limiter := w.server.perIPConnLimiter.Load(); limiter != nil && limits.MaxConnsPerIP > 0 && !w.server.trustedProxies.active {
			key := extractIP(c.remoteAddr)
			if !limiter.acquire(key, limits.MaxConnsPerIP) {
				c.fd = -1
				_ = unix.Close(nfd)
				w.pool.put(c)
				continue
			}
			c.ipHeld = true
			c.ipKey = key
		}
		c.writeBuf = c.writeBuf[:0]
		c.h2.appBufOff = 0
		c.tls = w.tlsMode
		c.tlsVersion = 0
		c.appBufOff = 0
		if c.appBuf != nil {
			c.appBuf = c.appBuf[:0]
		}
		if c.tls {
			c.phase = tlsConnPhaseClientHello
			c.hsReader = nil
			c.appReader = nil
			c.appWriter = nil
			c.tls12 = nil
			c.tlsRetry = nil
			c.ticket = nil
			c.clientAuth = nil
			c.tlsAlertSent = false
			c.peerCerts = nil
			c.tlsCertEntry = nil
			c.tlsPeerClosed = false
			c.tlsUselessRecords = 0
			c.cipherOff = 0
			c.selectedALPN = ""
		}
		for nfd >= len(w.conns) {
			w.conns = append(w.conns, make([]*epollConn, len(w.conns))...)
		}
		w.conns[nfd] = c
		ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(nfd)}
		if err := unix.EpollCtl(w.epfd, unix.EPOLL_CTL_ADD, nfd, &ev); err != nil {
			w.conns[nfd] = nil
			_ = unix.Close(nfd)
			w.pool.put(c)
		}
	}
}

const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

func acceptResourceExhausted(err error) bool {
	return err == unix.EMFILE || err == unix.ENFILE || err == unix.ENOBUFS || err == unix.ENOMEM
}

func (w *epollWorker) pauseAccept(now int64) {
	w.acceptBackoff = min(max(2*w.acceptBackoff, acceptBackoffMin), acceptBackoffMax)
	w.acceptResumeAt = now + int64(w.acceptBackoff)
	ev := unix.EpollEvent{Fd: int32(w.listenerFD)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, w.listenerFD, &ev)
}

func (w *epollWorker) resumeAcceptIfDue(now int64) bool {
	if now < w.acceptResumeAt {
		return false
	}
	w.acceptResumeAt = 0
	if w.listenerFD < 0 {
		return false
	}
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(w.listenerFD)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, w.listenerFD, &ev)
	return true
}

func (w *epollWorker) msUntilAcceptResume(now int64) int {
	if now >= w.acceptResumeAt {
		return 0
	}
	return int((w.acceptResumeAt-now)/int64(time.Millisecond)) + 1
}

func epollRemoteAddr(sa unix.Sockaddr) string {
	sa4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return ""
	}
	return net.IP(sa4.Addr[:]).String() + ":" + strconv.Itoa(sa4.Port)
}

func (w *epollWorker) readable(c *epollConn, peerClosed bool) {
	for w.readOnce(c, peerClosed) {
	}
}

func (w *epollWorker) readOnce(c *epollConn, peerClosed bool) (readAgain bool) {
	if c.lingering {
		w.discardLingering(c)
		return false
	}
	if peerClosed {
		c.peerHup = true
	}
	if c.tunnelPaused {
		if peerClosed {
			w.closeConn(c)
			return false
		}
		c.readPending = true
		return false
	}
	if c.dispatching && !c.h1BodyWantsInput() {
		c.readPending = true
		if peerClosed {
			c.cancelH1(ErrClientGone)
		}
		return false
	}
	c.readPending = false
	if c.readBuf == nil {
		c.readBuf = acquireEpollReadBuf()
	}
	if c.writeBuf == nil {
		c.writeBuf = acquireIOBuf()
	}
	maxRead := w.server.effectiveReadCap()
	prevReadN := c.readN
	closed := false
	bufferFull := false
	for {
		if cap(c.readBuf)-c.readN < plainReadMinFree {
			c.compactH2ReadBuffer(true)
			if cap(c.readBuf)-c.readN < plainReadMinFree {
				grown, ok := growPlainReadBuffer(c.readBuf[:c.readN], plainReadMinFree, maxRead)
				if !ok {
					bufferFull = true
					break
				}
				c.readBuf = grown[:cap(grown)]
			}
		}
		reqLen := cap(c.readBuf) - c.readN
		n, err := socketRecv(c.fd, c.readBuf[c.readN:cap(c.readBuf)])
		if n > 0 {
			w.bytesIn += uint64(n)
			c.readN += n
			if n < reqLen && !c.h1BodyDrainsToEOF() {
				break
			}
			if c.h1In != nil && c.readN >= h1BodyReadAhead {
				c.readPending = true
				break
			}
			continue
		}
		if n == 0 && err == nil {
			if c.h1BodyStreaming() {
				c.inputEOF = true
				break
			}
			closed = true
			break
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			break
		}
		w.closeConn(c)
		return false
	}
	if prevReadN == 0 && c.readN > 0 {
		keepDeadline := c.tls && c.deadline != 0 && (c.phase != tlsConnPhaseApplication && c.phase != tlsConnPhaseH2Native || len(c.appBuf) > 0)
		if !keepDeadline {
			c.deadline = deadlineFrom(w.nextReadTimeout(c))
		}
	}
	fullAt := c.bufferedInput()
	w.serviceBuffered(c, closed, peerClosed)
	if w.abortStarvedBody(c) {
		return false
	}
	if !bufferFull || closed || c.fd < 0 || c.lingering {
		return false
	}
	if c.dispatching {
		c.readPending = true
		return false
	}
	if c.bufferedInput() < fullAt {
		return true
	}
	w.closeConn(c)
	return false
}

// resumeConn continues a connection after an asynchronous dispatch. A read
// edge seen while the handler ran is honoured with a fresh read; otherwise
// only already-buffered input is processed, which spares a syscall per
// request on the common path.
func (w *epollWorker) resumeConn(c *epollConn) {
	if c.readPending {
		w.readable(c, false)
		return
	}
	if c.readBuf == nil {
		c.readBuf = acquireEpollReadBuf()
	}
	if c.writeBuf == nil {
		c.writeBuf = acquireIOBuf()
	}
	w.serviceBuffered(c, false, false)
}

func (w *epollWorker) serviceBuffered(c *epollConn, closed, peerClosed bool) {
	if c.readN > 0 || c.tlsAppPending() {
		var action int
		if c.tls {
			action = c.epollProcessTLS(w.server)
		} else {
			action = c.epollProcess(w.server)
		}
		if action == epollActionDetached {
			if c.inFlight == 0 {
				w.putTakenOver(c)
			}
			return
		}
		if action == epollActionProxyInFlight {
			// The upstream exchange owns this connection now. Only a client
			// that actually went away may tear it down here.
			if closed {
				w.closeConn(c)
				return
			}
			c.deadline = 0
			return
		}
		if action == epollActionCloseAfterFlush {
			c.closeAfter = true
		}
		if c.dispatching && !c.closeAfter {
			if len(c.writeBuf) > c.writeSent {
				w.markFlush(c)
			}
		} else if !w.flush(c) {
			return
		}
	}
	if closed {
		w.closeConn(c)
		return
	}
	if c.fd < 0 {
		return
	}
	if c.inFlight > 0 || c.dispatching {
		c.deadline = 0
		if c.h1BodyWantsInput() {
			c.deadline = deadlineFrom(w.readTO)
		}
		return
	}
	if peerClosed || c.inputEOF {
		if !c.outArmed && c.writeSent == len(c.writeBuf) {
			w.closeConn(c)
			return
		}
		c.closeAfter = true
	}
	if c.readN == 0 && !c.outArmed && c.writeSent == len(c.writeBuf) {
		releaseEpollReadBuf(c.readBuf)
		c.readBuf = nil
		releaseIOBuf(c.writeBuf)
		c.writeBuf = nil
		if c.appBuf != nil && len(c.appBuf) == 0 {
			releaseIOBuf(c.appBuf)
			c.appBuf = nil
		}
		if c.plainBuf != nil && len(c.plainBuf) == 0 {
			releaseIOBuf(c.plainBuf)
			c.plainBuf = nil
		}
		c.reqBodyCopy = shrinkEpollBuf(c.reqBodyCopy)
		c.req.Body = nil
		c.resp.resetFastH1()
		c.deadline = deadlineFrom(w.idleTO)
	}
}

func (c *epollConn) tlsAppPending() bool {
	return c.tls && (c.appBufOff < len(c.appBuf) || c.tlsPeerClosed)
}

func (c *epollConn) epollProcess(srv *Server) int {
	if c.protocol == plainConnProtoUnknown {
		avail := c.readN
		checkLen := avail
		if checkLen > H2PrefaceLen {
			checkLen = H2PrefaceLen
		}
		isPreface := true
		for i := 0; i < checkLen; i++ {
			if c.readBuf[i] != H2ClientPreface[i] {
				isPreface = false
				break
			}
		}
		if isPreface && srv.http2Enabled() {
			if avail < H2PrefaceLen {
				return epollActionNeedRead
			}
			c.protocol = plainConnProtoH2
			c.h2.init(srv.h2HeaderTableSize(), srv.h2HeaderListLimit())
			c.deadline = deadlineFrom(c.worker.readTO)
			c.writeBuf = appendH2ServerSettingsFlight(c.writeBuf, srv)
			Stats.H2Conns.Add(1)
		} else {
			c.protocol = plainConnProtoH1
			Stats.H1Conns.Add(1)
		}
	}
	if c.protocol == plainConnProtoTunnel {
		c.worker.tunnelToBackend(c)
		return epollActionNeedRead
	}
	if c.protocol == plainConnProtoH1 {
		return c.epollProcessH1(srv)
	}
	return c.epollProcessH2Frames(srv)
}

const epollMaxPendingWriteDefault = 8 << 20

func (w *epollWorker) flush(c *epollConn) bool {
	if c.lingering {
		return false
	}
	progressed := false
drain:
	for c.writeSent < len(c.writeBuf) {
		n, err := socketSend(c.fd, c.writeBuf[c.writeSent:])
		if n > 0 {
			w.bytesOut += uint64(n)
			c.writeSent += n
			progressed = true
			continue
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN {
			if len(c.writeBuf)-c.writeSent > w.maxPendingWrite {
				w.closeConn(c)
				return false
			}
			w.resumeRelayIfDrained(c)
			if c.fd < 0 {
				return false
			}
			if progressed && c.outArmed && w.writeTO > 0 {
				c.deadline = deadlineFrom(w.writeTO)
			}
			w.armOut(c)
			return true
		}
		w.closeConn(c)
		return false
	}
	c.writeBuf = c.writeBuf[:0]
	c.writeSent = 0
	if c.h2PumpAll(w) || c.h1PumpOut(w) {
		goto drain
	}
	if c.outArmed {
		w.disarmOut(c)
	}
	w.resumeRelayIfDrained(c)
	if c.fd < 0 {
		return false
	}
	if c.writeSent < len(c.writeBuf) {
		return true
	}
	if c.closeAfter {
		w.closeAfterResponse(c)
		return false
	}
	return true
}

func (w *epollWorker) armOut(c *epollConn) {
	if c.outArmed {
		return
	}
	c.outArmed = true
	if w.writeTO > 0 {
		c.deadline = deadlineFrom(w.writeTO)
	}
	ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLOUT|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(c.fd)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, c.fd, &ev)
}

func (w *epollWorker) disarmOut(c *epollConn) {
	c.outArmed = false
	if c.inFlight > 0 || c.dispatching {
		c.deadline = 0
	} else if w.idleTO > 0 {
		c.deadline = deadlineFrom(w.idleTO)
	}
	ev := unix.EpollEvent{Events: uint32(unix.EPOLLIN|unix.EPOLLRDHUP) | uint32(unix.EPOLLET&0xffffffff), Fd: int32(c.fd)}
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_MOD, c.fd, &ev)
}

func (w *epollWorker) closeConn(c *epollConn) {
	if c.fd < 0 {
		return
	}
	c.cancelInFlight(ErrClientGone)
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, c.fd, nil)
	_ = unix.Close(c.fd)
	if c.fd < len(w.conns) {
		w.conns[c.fd] = nil
	}
	c.fd = -1
	c.generation++
	c.releaseH1BodyBudget()
	w.abortProxyExchange(c)
	if c.tunnelBE != nil {
		w.closeTunnelFromClient(c)
	}
	c.flushQueued = false
	c.h2AbortAllStreaming()
	c.h1AbortOut()
	c.h1AbortIn()
	c.h2AbortAllBodyIn()
	c.lingering = false
	for id, stream := range c.h2.streams {
		if stream.asyncBusy {
			continue
		}
		stream.Reset()
		StreamPool.Put(stream)
		delete(c.h2.streams, id)
	}
	for id, stream := range c.h2.sending {
		stream.Reset()
		StreamPool.Put(stream)
		delete(c.h2.sending, id)
	}
	c.readN = 0
	c.writeSent = 0
	c.h1Off = 0
	c.chunkScanPos = 0
	c.writeBuf = c.writeBuf[:0]
	c.h2.appBufOff = 0
	c.protocol = plainConnProtoUnknown
	c.closeAfter = false
	c.outArmed = false
	c.dispatching = false
	c.readPending = false
	c.peerHup = false
	c.inputEOF = false
	c.h1ContinueSent = false
	c.hsReader = nil
	c.appReader = nil
	c.appWriter = nil
	c.tls12 = nil
	c.tlsRetry = nil
	c.ticket = nil
	c.clientAuth = nil
	c.tlsAlertSent = false
	c.peerCerts = nil
	c.tlsCertEntry = nil
	c.tlsPeerClosed = false
	c.tlsUselessRecords = 0
	c.cipherOff = 0
	c.h2GoingAway = false
	c.appBufOff = 0
	if c.appBuf != nil {
		c.appBuf = c.appBuf[:0]
	}
	c.tls = false
	c.tlsVersion = 0
	releaseEpollReadBuf(c.readBuf)
	c.readBuf = nil
	if c.ipHeld {
		w.server.perIPConnLimiter.Load().release(c.ipKey)
		c.ipHeld = false
		c.ipKey = ""
	}
	if c.inFlight > 0 {
		return
	}
	w.pool.put(c)
}

func (c *epollConn) acquireIPConn(srv *Server, req *Request) bool {
	if srv.trustedProxies.active {
		applyTrustedRealIP(req, srv.trustedProxies)
	}
	return true
}

func (c *epollConn) compactH2ReadBuffer(force bool) {
	st := &c.h2
	if st.appBufOff == 0 {
		return
	}
	if !force && st.appBufOff <= cap(c.readBuf)/2 {
		return
	}
	remaining := c.readN - st.appBufOff
	if remaining > 0 {
		copy(c.readBuf, c.readBuf[st.appBufOff:c.readN])
	}
	c.readN = remaining
	st.appBufOff = 0
}

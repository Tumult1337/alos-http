package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/guno1928/alos-http/core"
	"github.com/guno1928/turbo"
)

const (
	exitUnsupported      = 64
	plaintextBody        = "Hello, World!"
	mwBody               = "ok"
	pangram              = "The quick brown fox jumps over the lazy dog. "
	text16kSize          = 16384
	bytes64kSize         = 64 << 10
	bytes1mSize          = 1 << 20
	rateLimitMaxRequests = 1_000_000_000
	rateLimitWindow      = time.Second
	readyPollInterval    = 10 * time.Millisecond
	readyDialTimeout     = 150 * time.Millisecond
	readyMaxWait         = 30 * time.Second
	certDomain           = "localhost"
)

type options struct {
	proto      string
	mode       string
	addr       string
	cert       string
	key        string
	static     string
	origin     string
	cpuprofile string
	memprofile string
}

type message struct {
	Message string `json:"message"`
}

func parseOptions() options {
	var o options
	flag.StringVar(&o.proto, "proto", "h1", "h1|tls|h2c|h2")
	flag.StringVar(&o.mode, "mode", "app", "app|proxy")
	flag.StringVar(&o.addr, "addr", "127.0.0.1:18080", "listen address")
	flag.StringVar(&o.cert, "cert", "", "PEM certificate file")
	flag.StringVar(&o.key, "key", "", "PEM private key file")
	flag.StringVar(&o.static, "static", "", "static file root")
	flag.StringVar(&o.origin, "origin", "127.0.0.1:18090", "proxy origin host:port")
	flag.StringVar(&o.cpuprofile, "cpuprofile", "", "write CPU profile to file")
	flag.StringVar(&o.memprofile, "memprofile", "", "write heap profile to file")
	flag.Parse()
	return o
}

func isTLSProto(proto string) bool {
	return proto == "tls" || proto == "h2"
}

func validate(o options) {
	switch o.proto {
	case "h1", "tls", "h2c", "h2":
	default:
		fmt.Printf("UNSUPPORTED %s: unknown protocol\n", o.proto)
		os.Exit(exitUnsupported)
	}
	if o.mode != "app" && o.mode != "proxy" {
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", o.mode)
		os.Exit(2)
	}
}

func buildConfig(o options) core.Config {
	cfg := core.Config{
		Addr:          o.addr,
		MaxConnsPerIP: -1,
		MaxConns:      -1,
	}
	if isTLSProto(o.proto) {
		cfg.Certs = []core.CertConfig{{
			Domain:   certDomain,
			CertFile: o.cert,
			KeyFile:  o.key,
			Source:   core.CertManual,
		}}
		cfg.DefaultDomain = certDomain
	} else {
		cfg.PlainHTTP = true
	}
	cfg.InlineHandlers = os.Getenv("ALOS_INLINE") == "1"
	cfg.DisableInlineHandlers = os.Getenv("ALOS_NO_INLINE") == "1"
	return cfg
}

func repeatToSize(pattern string, size int) string {
	return strings.Repeat(pattern, size/len(pattern)+1)[:size]
}

func registerAppRoutes(r *core.Router, staticRoot string) {
	bytes64k := bytes.Repeat([]byte{'x'}, bytes64kSize)
	bytes1m := bytes.Repeat([]byte{'x'}, bytes1mSize)
	text16k := repeatToSize(pangram, text16kSize)

	plaintext := func(req *core.Request, resp *core.Response) {
		resp.String(plaintextBody)
	}
	plaintextRoute := r.GET("/plaintext", plaintext)
	if os.Getenv("ALOS_ROUTE_INLINE") == "1" {
		plaintextRoute.Inline()
	}
	r.GET("/", plaintext)
	r.GET("/json", func(req *core.Request, resp *core.Response) {
		_ = resp.JSONMarshal(message{Message: plaintextBody})
	})
	r.GET("/user/:id", func(req *core.Request, resp *core.Response) {
		resp.String(req.ParamValue("id"))
	})
	r.POST("/echo", func(req *core.Request, resp *core.Response) {
		resp.String(strconv.Itoa(len(req.Body)))
	})
	if os.Getenv("ALOS_SHARED_BODY") == "1" {
		shared64k, shared1m := string(bytes64k), string(bytes1m)
		r.GET("/bytes/64k", func(req *core.Request, resp *core.Response) {
			resp.String(shared64k).ContentType = "application/octet-stream"
		})
		r.GET("/bytes/1m", func(req *core.Request, resp *core.Response) {
			resp.String(shared1m).ContentType = "application/octet-stream"
		})
	} else {
		r.GET("/bytes/64k", func(req *core.Request, resp *core.Response) {
			resp.BytesNoCopy(bytes64k)
		})
		r.GET("/bytes/1m", func(req *core.Request, resp *core.Response) {
			resp.BytesNoCopy(bytes1m)
		})
	}
	r.GET("/static/*filepath", core.Static("/static", core.StaticConfig{Root: staticRoot}))
	r.GET("/text16k", core.Chain(func(req *core.Request, resp *core.Response) {
		resp.String(text16k)
	}, core.Compress(core.CompressConfig{})))
	r.GET("/browser", func(req *core.Request, resp *core.Response) {
		resp.String(req.Header("User-Agent") + "|" + req.Header("Accept-Language") + "|" + req.Cookie("sid"))
	})
	r.GET("/mw", core.Chain(func(req *core.Request, resp *core.Response) {
		resp.String(mwBody)
	},
		core.CORS(core.CORSConfig{AllowOrigins: []string{"*"}}),
		core.RateLimitMiddleware(core.RateLimitMiddlewareConfig{MaxRequests: rateLimitMaxRequests, Window: rateLimitWindow}),
	))
	r.GET("/ws", func(req *core.Request, resp *core.Response) {
		core.ServeWebSocketEvents(req, resp, core.WSUpgradeOptions{}, core.WSEventHandler{OnMessage: echoWebSocket})
	})
}

func echoWebSocket(ws *core.WSConn, opcode byte, msg []byte) {
	_ = ws.WriteMessage(opcode, msg)
}

func proxyDomains(listenAddr string) []string {
	domains := []string{"127.0.0.1", "localhost"}
	host, _, err := net.SplitHostPort(listenAddr)
	if err == nil && host != "" && host != domains[0] && host != domains[1] {
		domains = append(domains, host)
	}
	return domains
}

func registerProxy(s *core.Server, listenAddr, origin string) {
	for _, domain := range proxyDomains(listenAddr) {
		s.AddProxyDomain(core.DomainConfig{
			Domain:   domain,
			Backends: []core.BackendConfig{{Addr: origin}},
		})
	}
}

func serve(s *core.Server, proto string) error {
	if isTLSProto(proto) {
		return s.ListenAndServeTLS()
	}
	return s.ListenAndServe()
}

func ensurePortFree(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "address %s is already in use (a stale server would silently share it via SO_REUSEPORT): %v\n", addr, err)
		os.Exit(1)
	}
	_ = ln.Close()
}

func waitUntilAccepting(addr string) bool {
	deadline := turbo.Deadline(readyMaxWait)
	for turbo.Until(deadline) > 0 {
		conn, err := net.DialTimeout("tcp", addr, readyDialTimeout)
		if err == nil {
			_ = conn.Close()
			return true
		}
		turbo.Sleep(readyPollInterval)
	}
	return false
}

func startCPUProfile(path string) {
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cpuprofile: %v\n", err)
		os.Exit(1)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		fmt.Fprintf(os.Stderr, "cpuprofile: %v\n", err)
		os.Exit(1)
	}
}

func writeProfiles(o options) {
	if o.cpuprofile != "" {
		pprof.StopCPUProfile()
	}
	if o.memprofile == "" {
		return
	}
	f, err := os.Create(o.memprofile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "memprofile: %v\n", err)
		return
	}
	runtime.GC()
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(os.Stderr, "memprofile: %v\n", err)
	}
	_ = f.Close()
}

type allocSampler struct {
	mallocs uint64
	bytes   uint64
}

func (a *allocSampler) sample() (mallocs, totalBytes uint64) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	mallocs, totalBytes = ms.Mallocs-a.mallocs, ms.TotalAlloc-a.bytes
	a.mallocs, a.bytes = ms.Mallocs, ms.TotalAlloc
	return mallocs, totalBytes
}

func handleSignals(o options) {
	var sampler allocSampler
	sampler.sample()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)
	for sig := range sigs {
		if sig == syscall.SIGUSR1 {
			mallocs, totalBytes := sampler.sample()
			fmt.Fprintf(os.Stderr, "mallocs=%d bytes=%d\n", mallocs, totalBytes)
			continue
		}
		writeProfiles(o)
		os.Exit(0)
	}
}

func main() {
	o := parseOptions()
	validate(o)
	ensurePortFree(o.addr)
	startCPUProfile(o.cpuprofile)

	s := core.New(buildConfig(o))
	if o.mode == "proxy" {
		registerProxy(s, o.addr, o.origin)
	} else {
		registerAppRoutes(s.Router, o.static)
	}

	go handleSignals(o)

	serveErr := make(chan error, 1)
	go func() { serveErr <- serve(s, o.proto) }()

	ready := make(chan bool, 1)
	go func() { ready <- waitUntilAccepting(o.addr) }()

	select {
	case err := <-serveErr:
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	case ok := <-ready:
		if !ok {
			fmt.Fprintf(os.Stderr, "server did not start accepting on %s\n", o.addr)
			os.Exit(1)
		}
	}
	fmt.Println("READY")
	fmt.Fprintf(os.Stderr, "gomaxprocs=%d numcpu=%d\n", runtime.GOMAXPROCS(0), runtime.NumCPU())

	if err := <-serveErr; err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/proxy"
	"github.com/gofiber/fiber/v3/middleware/static"
)

const (
	exitUnsupported = 64
	exitUsage       = 2
	exitFailure     = 1

	helloText       = "Hello, World!"
	foxSentence     = "The quick brown fox jumps over the lazy dog. "
	text16kSize     = 16384
	bytes64kSize    = 65536
	bytes1mSize     = 1048576
	rateLimitMax    = 1_000_000_000
	rateLimitWindow = time.Second

	http2Unsupported = "Fiber v3.6.1 runs on fasthttp v1.75.0, which has no HTTP/2 server (fasthttp README FAQ \"Why fasthttp doesn't support HTTP/2.0\"; Fiber docs/guide/reverse-proxy.md recommends a reverse proxy for HTTP/2)"
)

type options struct {
	proto      string
	mode       string
	addr       string
	cert       string
	key        string
	staticRoot string
	origin     string
	prefork    bool
}

type jsonMessage struct {
	Message string `json:"message"`
}

type childRegistry struct {
	mu   sync.Mutex
	pids []int
}

func (r *childRegistry) add(pid int) error {
	r.mu.Lock()
	r.pids = append(r.pids, pid)
	r.mu.Unlock()
	return nil
}

func (r *childRegistry) signalAll(sig syscall.Signal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pid := range r.pids {
		_ = syscall.Kill(pid, sig)
	}
}

func main() {
	opts := parseOptions()

	switch opts.proto {
	case "h1", "tls":
	case "h2c", "h2":
		fmt.Printf("UNSUPPORTED %s: %s\n", opts.proto, http2Unsupported)
		os.Exit(exitUnsupported)
	default:
		fail(exitUsage, "unknown -proto "+opts.proto)
	}

	app := fiber.New()

	switch opts.mode {
	case "app":
		registerAppRoutes(app, opts.staticRoot)
	case "proxy":
		registerProxy(app, opts.origin)
	default:
		fail(exitUsage, "unknown -mode "+opts.mode)
	}

	if opts.prefork && !fiber.IsChild() {
		superviseChildren(app)
	} else {
		reportMemStatsOnSignal()
	}

	if err := app.Listen(opts.addr, listenConfig(opts)); err != nil {
		fail(exitFailure, err.Error())
	}
}

func parseOptions() options {
	var opts options
	flag.StringVar(&opts.proto, "proto", "h1", "h1|tls|h2c|h2")
	flag.StringVar(&opts.mode, "mode", "app", "app|proxy")
	flag.StringVar(&opts.addr, "addr", "127.0.0.1:18080", "listen address")
	flag.StringVar(&opts.cert, "cert", "/root/alos-perf/harness/certs/cert.pem", "TLS certificate")
	flag.StringVar(&opts.key, "key", "/root/alos-perf/harness/certs/key.pem", "TLS key")
	flag.StringVar(&opts.staticRoot, "static", "/root/alos-perf/harness/static", "static file root")
	flag.StringVar(&opts.origin, "origin", "127.0.0.1:18090", "proxy origin host:port")
	flag.BoolVar(&opts.prefork, "prefork", false, "enable Fiber prefork")
	flag.Parse()
	return opts
}

func fail(code int, message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(code)
}

func registerAppRoutes(app *fiber.App, staticRoot string) {
	text16k := []byte(strings.Repeat(foxSentence, text16kSize/len(foxSentence)+1)[:text16kSize])
	bytes64k := []byte(strings.Repeat("x", bytes64kSize))
	bytes1m := []byte(strings.Repeat("x", bytes1mSize))

	plaintext := func(c fiber.Ctx) error {
		return c.SendString(helloText)
	}

	app.Get("/plaintext", plaintext)
	app.Get("/", plaintext)
	app.Get("/json", func(c fiber.Ctx) error {
		return c.JSON(jsonMessage{Message: helloText})
	})
	app.Get("/user/:id", func(c fiber.Ctx) error {
		return c.SendString(c.Params("id"))
	})
	app.Post("/echo", func(c fiber.Ctx) error {
		return c.SendString(strconv.Itoa(len(c.Body())))
	})
	app.Get("/bytes/64k", octetStream(bytes64k))
	app.Get("/bytes/1m", octetStream(bytes1m))
	app.Use("/static", static.New(staticRoot))
	app.Get("/text16k", compress.New(), func(c fiber.Ctx) error {
		return c.Send(text16k)
	})
	app.Get("/browser", func(c fiber.Ctx) error {
		return c.SendString(c.Get(fiber.HeaderUserAgent) + "|" + c.Get(fiber.HeaderAcceptLanguage) + "|" + c.Cookies("sid"))
	})
	app.Get("/mw",
		cors.New(cors.Config{AllowOrigins: []string{"*"}}),
		limiter.New(limiter.Config{Max: rateLimitMax, Expiration: rateLimitWindow}),
		func(c fiber.Ctx) error {
			return c.SendString("ok")
		},
	)
	app.Get("/ws", websocket.New(echoWebSocket))
}

func octetStream(body []byte) fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMEOctetStream)
		return c.Send(body)
	}
}

func echoWebSocket(conn *websocket.Conn) {
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(messageType, message); err != nil {
			return
		}
	}
}

func registerProxy(app *fiber.App, origin string) {
	policy := proxy.DefaultSecurityPolicy()
	policy.AllowPrivateIPs = true
	app.Use(proxy.Balancer(proxy.Config{
		Servers:        []string{"http://" + origin},
		SecurityPolicy: &policy,
		ModifyRequest: func(c fiber.Ctx) error {
			c.Request().URI().SetScheme("http")
			return nil
		},
	}))
}

func listenConfig(opts options) fiber.ListenConfig {
	cfg := fiber.ListenConfig{
		DisableStartupMessage: true,
		EnablePrefork:         opts.prefork,
		ListenerAddrFunc: func(net.Addr) {
			announceListening()
		},
	}
	if opts.proto == "tls" {
		cfg.CertFile = opts.cert
		cfg.CertKeyFile = opts.key
		cfg.TLSConfigFunc = func(tlsConfig *tls.Config) {
			tlsConfig.NextProtos = []string{"http/1.1"}
		}
	}
	return cfg
}

func readinessSocketAddr(masterPID int) *net.UnixAddr {
	return &net.UnixAddr{Name: "@perfcompare-fiber-ready-" + strconv.Itoa(masterPID), Net: "unixgram"}
}

func announceListening() {
	if !fiber.IsChild() {
		fmt.Println("READY")
		return
	}
	conn, err := net.DialUnix("unixgram", nil, readinessSocketAddr(os.Getppid()))
	if err != nil {
		fail(exitFailure, "prefork readiness: "+err.Error())
	}
	_, _ = conn.Write([]byte{1})
	_ = conn.Close()
}

func superviseChildren(app *fiber.App) {
	children := &childRegistry{}
	app.Hooks().OnFork(children.add)

	memStatsRequests := make(chan os.Signal, 1)
	signal.Notify(memStatsRequests, syscall.SIGUSR1)
	go func() {
		for range memStatsRequests {
			children.signalAll(syscall.SIGUSR1)
		}
	}()

	readiness, err := net.ListenUnixgram("unixgram", readinessSocketAddr(os.Getpid()))
	if err != nil {
		fail(exitFailure, "prefork readiness: "+err.Error())
	}
	go func() {
		datagram := make([]byte, 1)
		for range runtime.GOMAXPROCS(0) {
			if _, _, err := readiness.ReadFromUnix(datagram); err != nil {
				fail(exitFailure, "prefork readiness: "+err.Error())
			}
		}
		fmt.Println("READY")
		for {
			if _, _, err := readiness.ReadFromUnix(datagram); err != nil {
				return
			}
		}
	}()
}

func reportMemStatsOnSignal() {
	requests := make(chan os.Signal, 1)
	signal.Notify(requests, syscall.SIGUSR1)
	var previous runtime.MemStats
	runtime.ReadMemStats(&previous)
	go func() {
		for range requests {
			var current runtime.MemStats
			runtime.ReadMemStats(&current)
			fmt.Fprintf(os.Stderr, "mallocs=%d bytes=%d\n", current.Mallocs-previous.Mallocs, current.TotalAlloc-previous.TotalAlloc)
			previous = current
		}
	}()
}

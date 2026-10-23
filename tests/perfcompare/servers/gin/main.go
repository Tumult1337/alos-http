package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const (
	exitUsage   = 2
	exitFailure = 1

	helloText    = "Hello, World!"
	foxSentence  = "The quick brown fox jumps over the lazy dog. "
	text16kSize  = 16384
	bytes64kSize = 65536
	bytes1mSize  = 1048576

	proxyMaxIdleConns     = 1024
	proxyIdleConnTimeout  = 90 * time.Second
	octetStreamMediaType  = "application/octet-stream"
	userAgentHeader       = "User-Agent"
	acceptLanguageHeader  = "Accept-Language"
	sessionCookieName     = "sid"
	middlewareRouteAnswer = "ok"
)

type options struct {
	proto      string
	mode       string
	addr       string
	cert       string
	key        string
	staticRoot string
	origin     string
}

type jsonMessage struct {
	Message string `json:"message"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func main() {
	opts := parseOptions()

	protocols, useTLS := protocolsFor(opts.proto)

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()

	switch opts.mode {
	case "app":
		registerAppRoutes(engine, opts.staticRoot)
	case "proxy":
		registerProxy(engine, opts.origin)
	default:
		fail(exitUsage, "unknown -mode "+opts.mode)
	}

	server := &http.Server{Handler: engine, Protocols: protocols}

	listener, err := net.Listen("tcp", opts.addr)
	if err != nil {
		fail(exitFailure, err.Error())
	}

	reportMemStatsOnSignal()
	fmt.Println("READY")

	if useTLS {
		err = server.ServeTLS(listener, opts.cert, opts.key)
	} else {
		err = server.Serve(listener)
	}
	if err != nil {
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
	flag.Parse()
	return opts
}

func fail(code int, message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(code)
}

func protocolsFor(proto string) (*http.Protocols, bool) {
	protocols := &http.Protocols{}
	protocols.SetHTTP1(true)
	switch proto {
	case "h1":
		return protocols, false
	case "h2c":
		protocols.SetUnencryptedHTTP2(true)
		return protocols, false
	case "tls", "h2":
		protocols.SetHTTP2(true)
		return protocols, true
	}
	fail(exitUsage, "unknown -proto "+proto)
	return nil, false
}

func registerAppRoutes(engine *gin.Engine, staticRoot string) {
	text16k := strings.Repeat(foxSentence, text16kSize/len(foxSentence)+1)[:text16kSize]
	bytes64k := []byte(strings.Repeat("x", bytes64kSize))
	bytes1m := []byte(strings.Repeat("x", bytes1mSize))

	plaintext := func(c *gin.Context) {
		c.String(http.StatusOK, helloText)
	}

	engine.GET("/plaintext", plaintext)
	engine.GET("/", plaintext)
	engine.GET("/json", func(c *gin.Context) {
		c.JSON(http.StatusOK, jsonMessage{Message: helloText})
	})
	engine.GET("/user/:id", func(c *gin.Context) {
		c.String(http.StatusOK, c.Param("id"))
	})
	engine.POST("/echo", func(c *gin.Context) {
		body, err := c.GetRawData()
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		c.String(http.StatusOK, strconv.Itoa(len(body)))
	})
	engine.GET("/bytes/64k", octetStream(bytes64k))
	engine.GET("/bytes/1m", octetStream(bytes1m))
	engine.Static("/static", staticRoot)
	engine.GET("/text16k", gzip.Gzip(gzip.DefaultCompression), func(c *gin.Context) {
		c.String(http.StatusOK, text16k)
	})
	engine.GET("/browser", func(c *gin.Context) {
		sid, _ := c.Cookie(sessionCookieName)
		c.String(http.StatusOK, c.GetHeader(userAgentHeader)+"|"+c.GetHeader(acceptLanguageHeader)+"|"+sid)
	})
	engine.GET("/mw", cors.New(cors.Config{AllowAllOrigins: true}), func(c *gin.Context) {
		c.String(http.StatusOK, middlewareRouteAnswer)
	})
	engine.GET("/ws", echoWebSocket)
}

func octetStream(body []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Data(http.StatusOK, octetStreamMediaType, body)
	}
}

func echoWebSocket(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer conn.Close()
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

func registerProxy(engine *gin.Engine, origin string) {
	target := &url.URL{Scheme: "http", Host: origin}
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
		},
		Transport: &http.Transport{
			MaxIdleConns:        proxyMaxIdleConns,
			MaxIdleConnsPerHost: proxyMaxIdleConns,
			IdleConnTimeout:     proxyIdleConnTimeout,
			DisableCompression:  true,
		},
	}
	engine.Any("/*path", gin.WrapH(reverseProxy))
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

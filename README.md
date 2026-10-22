# ALOS HTTP - Go web framework on a custom epoll networking stack

> **Linux x86-64 only.** ALOS HTTP requires **Linux** on **amd64 (x86-64)** CPUs. It does not support Windows, macOS, ARM, or any other OS/architecture combination. If you are on Windows or macOS, use Docker or a Linux VM to run it.

> **Work in progress.** ALOS HTTP is still under active development and bugs may be present. If you find a bug or rough edge, please open a GitHub issue.
>
> **Join the Discord:** [https://alos.gg/discord](https://alos.gg/discord)

In the benchmark suite below, ALOS HTTP had the highest throughput in **184 of 185** head-to-head comparisons against Fiber v3, gin, xitca-web and ntex, across plain HTTP/1.1, HTTPS, h2c and HTTP/2 over TLS. The one exception is listed in [Benchmarks](#benchmarks).

ALOS HTTP is a Linux-only Go web framework, Go HTTP server, and application server built around a custom networking stack running on a hand-built, edge-triggered `epoll` event loop. It only runs on **Linux amd64 (x86-64)** — the entire I/O layer, including HTTP/1.1, HTTP/2, HTTP/3 (QUIC), TLS, and reverse proxying, is built on a custom `epoll` backend and amd64-specific optimizations.

It includes first-class TLS handling, HTTP/1.1, HTTP/2, and HTTP/3 support, reverse proxying, load balancing, rate limiting, streaming, ACME automation, and a high-performance radix router.

It is designed for people who want more control than a thin net/http wrapper, while still getting an ergonomic handler API.

If you are looking for a high-performance Go web server or Go reverse proxy for Linux, ALOS HTTP is focused on the Linux fast path and its custom `epoll` networking stack rather than maintaining cross-platform behavior.

Official repository:
https://github.com/guno1928/alos-http

## Why ALOS HTTP

ALOS HTTP focuses on a different part of the stack than most Go web frameworks.

- Custom server core instead of delegating everything to net/http.
- Built-in HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) serving.
- Linux amd64 runtime on a custom `epoll` event-loop backend.
- Handlers run directly on the event loop by default, with an automatic hand-off for slow handlers.
- Built-in TLS 1.3 and 1.2 with ACME support for HTTPS and TLS automation.
- High-performance radix router with params, wildcards, groups, and middleware.
- Reverse proxy with load balancing, health checks, and cache support.
- Response streaming, static files and file sending helpers.
- Middleware for recovery, logging, CORS, gzip and brotli compression, auth, timeouts, security headers, and more.
- Rate limiting primitives and rule-driven limiting.

### Custom epoll networking stack

On Linux amd64, ALOS HTTP runs its entire I/O layer on a hand-built, edge-triggered `epoll` event loop instead of `net/http`:

- **TCP accept** — inbound connections are accepted on per-worker `SO_REUSEPORT` listeners, sharded across cores (by default one listener per `GOMAXPROCS` thread, capped at 128).
- **TLS record I/O** — a hand-rolled TLS 1.3 (and 1.2) record layer handles read, decrypt, encrypt, and write directly on the event loop, using AES-NI.
- **Plain HTTP I/O** — non-TLS HTTP/1.1 and HTTP/2 read/write paths run directly on the epoll loop, with per-connection response batching.
- **Reverse proxy egress** — outbound connections to backends (dial, send, receive) run over standard sockets.
- **Static files** — plain HTTP/1.1 static files are sent with `sendfile(2)`; TLS and HTTP/2 connections stream file data through the event loop.
- **HTTP/2 framing** — HTTP/2 frame reads and writes on both the ingress and shared-bridge proxy paths run on the event loop.
- **HTTP/3 (QUIC)** — UDP socket I/O for QUIC uses `epoll` with `recvmmsg`/`sendmmsg` and UDP GSO batching, plus `SO_REUSEPORT` for multi-listener scaling.

The hot path is edge-triggered and close to allocation-free: requests are parsed, routed, and served without `net/http`, interface dispatch, or reflection.

Search-friendly summary:

- Go web framework
- Go HTTP server
- Linux web server
- custom `epoll` networking stack
- reverse proxy and load balancer
- HTTP/1.1, HTTP/2, and HTTP/3 server
- QUIC server
- TLS 1.3 and ACME automation

## Platform Support

| | Supported |
|---|---|
| **OS** | Linux only |
| **Architecture** | amd64 (x86-64) only |
| **Go version** | Go 1.26.9+ |
| **Kernel** | Modern Linux; 4.18+ recommended for the HTTP/3 UDP GSO fast path |

- **Linux amd64 is the only supported platform.** ARM, RISC-V, 32-bit, Windows, macOS, and FreeBSD are not supported.
- The entire I/O stack (TCP accept, TLS, HTTP/1.1, HTTP/2, HTTP/3 QUIC, reverse proxy, sendfile) runs on a custom `epoll` event loop with `SO_REUSEPORT` sharding and amd64-specific optimizations.
- Hand-written amd64 assembly is used in hot paths: HTTP/1.1 request-line and header scanning, CRLF search, and WebSocket masking.
- If you are developing on Windows or macOS, edit code locally and deploy/test on Linux via Docker or a Linux VM.
- For HTTP/3 (QUIC over UDP), the server uses `epoll`-driven UDP sockets with `recvmmsg`/`sendmmsg`, UDP GSO batching, and `SO_REUSEPORT`.

## How ALOS serves requests

ALOS HTTP does not use `net/http` for serving. It runs a custom, edge-triggered `epoll` event loop written for Linux amd64.

Very simple version:

- `net/http` gives every connection its own goroutine that blocks on read/write syscalls.
- ALOS runs a small pool of event-loop workers that watch many connections at once with `epoll` and only touch a connection when it is actually ready.

Why that matters for ALOS HTTP:

- less per-connection overhead and memory
- `SO_REUSEPORT` sharding scales the accept and serve path across all cores
- per-connection response batching and a short-read fast path cut syscalls
- lower latency on hot paths, and efficient handling of many active connections

### Handler dispatch

By default, handlers run directly on the event-loop thread (HTTP/1.1 and HTTP/2), so a request has no goroutine hand-off or wake-up at all.

Slow handlers are handled automatically:

- If a handler holds the loop for more than about 2 ms (a sleep, a database call, a slow upstream), the loop is handed to a fresh goroutine so the other connections on that worker keep being served.
- That route then moves to goroutine dispatch, and returns to inline dispatch after it proves fast again.
- Handlers that stream, hijack or upgrade the connection (WebSocket) leave the loop as soon as they do so.
- Requests with streamed bodies, and every request on a server that also runs the reverse proxy, use goroutine dispatch.

You can change the default:

```go
srv := core.New(core.Config{
    Addr:                  ":8443",
    DisableInlineHandlers: true,
})

srv.Router.GET("/fast", func(req *core.Request, resp *core.Response) {
    resp.Status(200).String("ok")
}).Inline()
```

- `DisableInlineHandlers: true` hands every request to a goroutine, except routes marked with `.Inline()`.
- `InlineHandlers: true` additionally buffers request bodies that would otherwise be streamed, so those requests run on the loop too.

## Testing

The `core` package has 1,571 tests in 411 test files covering HTTP/1.1, HTTP/2, HTTP/3, TLS, WebSocket, routing, middleware, compression, static files, the reverse proxy and the DoS limits.

Latest run on the benchmark machine (2026-10-21):

| Check | Result |
| --- | --- |
| `go vet ./...` and `go build ./...` | clean |
| `go test ./core` | pass (336 s) |
| `go test ./...` (other packages) | pass |
| `go test -race` (dispatch, TLS and HTTP/1.1 write-path suites) | pass, 0 data races |
| OpenSSL 3.0.13 `s_client` interop (TLS 1.3/1.2, HRR, EMS, OCSP stapling, mTLS, resumption) | 17 passed, 0 failed |

## Benchmarks

All numbers are requests per second (mean of 2 rounds). Higher is better; the best result in each row is in bold. A dash means the framework has no support for that protocol or feature, or its test server failed the pre-run correctness check for that row.

#### HTTP/1.1 (plain)

| Workload | ALOS HTTP | Fiber v3 | gin | xitca-web | ntex |
| --- | --- | --- | --- | --- | --- |
| Plaintext `/plaintext` | **503.9k** | 400.5k | 217.2k | 446.6k | 437.0k |
| Root `/` | **500.5k** | 409.4k | 218.5k | 450.4k | 444.2k |
| JSON `/json` | **470.4k** | 373.4k | 209.7k | 436.5k | 431.0k |
| Route param `/user/:id` | **469.3k** | 395.1k | 217.8k | 435.2k | 420.0k |
| POST 1 KiB echo | **464.7k** | 370.8k | 173.0k | 408.9k | 380.8k |
| 64 KiB response body | 120.4k | 113.3k | 97.5k | 82.5k | **128.0k** |
| 1 MiB response body | **10.0k** | 9228 | 8856 | 5470 | 8504 |
| 64 KiB static file | **164.5k** | 117.4k | 47.7k | 17.3k | 50.8k |
| 16 KiB text, gzip | **224.9k** | 105.8k | 50.7k | 140.4k | 41.2k |
| 16 KiB text, brotli | **172.5k** | 129.3k | — | 110.4k | — |
| Browser-like request headers | **401.6k** | 311.6k | 147.1k | 343.2k | 349.6k |
| Middleware chain | **475.2k** | 318.5k | 214.6k | 348.4k | 423.6k |
| WebSocket echo, 64 B | **491.3k** | 395.2k | 408.9k | 459.4k | 473.0k |
| WebSocket echo, 16 KiB | **223.3k** | 119.6k | 90.4k | 112.7k | 144.2k |
| Reverse proxy to an ALOS origin | **187.6k** | 123.7k | 45.0k | — | — |
| `Connection: close` (new connection per request) | **71.9k** | 71.1k | 61.1k | 66.8k | 66.5k |

#### HTTPS (HTTP/1.1 over TLS 1.3)

| Workload | ALOS HTTP | Fiber v3 | gin | xitca-web | ntex |
| --- | --- | --- | --- | --- | --- |
| Plaintext `/plaintext` | **273.8k** | 247.9k | 158.0k | 254.1k | 257.4k |
| Root `/` | **285.2k** | 251.9k | 160.0k | 253.2k | 254.6k |
| JSON `/json` | **269.9k** | 236.6k | 155.5k | 249.6k | 252.6k |
| Route param `/user/:id` | **272.8k** | 246.4k | 160.6k | 250.8k | 252.6k |
| POST 1 KiB echo | **247.1k** | 221.2k | 133.7k | 230.6k | 224.7k |
| 64 KiB response body | **42.5k** | 41.5k | 41.0k | 35.2k | 39.7k |
| 1 MiB response body | **3300** | 3096 | 3092 | 2202 | 2529 |
| 64 KiB static file | **41.3k** | 34.0k | 29.4k | 13.8k | 25.3k |
| 16 KiB text, gzip | **171.3k** | 90.1k | 45.3k | 116.1k | 42.0k |
| 16 KiB text, brotli | **137.2k** | 107.3k | — | 94.0k | — |
| Browser-like request headers | **243.1k** | 206.1k | 117.9k | 207.9k | 223.3k |
| Middleware chain | **273.2k** | 211.9k | 159.8k | 218.4k | 245.7k |
| WebSocket echo, 64 B | **366.5k** | 297.0k | 300.8k | 334.7k | 356.9k |
| WebSocket echo, 16 KiB | **98.4k** | 71.0k | 59.7k | 65.7k | 78.2k |
| Reverse proxy to an ALOS origin | **138.6k** | 99.6k | 38.9k | — | — |
| `Connection: close` (new connection per request) | **7987** | 7434 | 7321 | 5008 | 5049 |

#### h2c (HTTP/2, plain)

Fiber v3 runs on fasthttp, which has no HTTP/2 server.

| Workload | ALOS HTTP | Fiber v3 | gin | xitca-web | ntex |
| --- | --- | --- | --- | --- | --- |
| Plaintext `/plaintext` | **2.23M** | — | 144.7k | 1.48M | 950.3k |
| Root `/` | **2.31M** | — | 144.0k | 1.55M | 1.04M |
| JSON `/json` | **2.00M** | — | 143.7k | 1.42M | 922.6k |
| Route param `/user/:id` | **2.10M** | — | 144.6k | 1.43M | 861.6k |
| POST 1 KiB echo | **1.21M** | — | 109.9k | 811.2k | 399.0k |
| 64 KiB response body | **99.3k** | — | 49.2k | 77.6k | 75.1k |
| 1 MiB response body | **7878** | — | 6734 | — | 6119 |
| 64 KiB static file | **96.6k** | — | 29.6k | 15.7k | 35.1k |
| 16 KiB text, gzip | **203.1k** | — | 37.7k | 126.1k | 38.5k |
| 16 KiB text, brotli | **156.8k** | — | — | 100.5k | — |
| Browser-like request headers | **1.09M** | — | 104.9k | 737.2k | 561.3k |
| Middleware chain | **1.99M** | — | 147.4k | 889.7k | 891.2k |

#### HTTP/2 over TLS 1.3

| Workload | ALOS HTTP | Fiber v3 | gin | xitca-web | ntex |
| --- | --- | --- | --- | --- | --- |
| Plaintext `/plaintext` | **2.04M** | — | 139.3k | 1.37M | 890.3k |
| Root `/` | **2.12M** | — | 133.9k | 1.42M | 959.4k |
| JSON `/json` | **1.83M** | — | 128.3k | 1.31M | 860.1k |
| Route param `/user/:id` | **1.99M** | — | 130.9k | 1.34M | 804.8k |
| POST 1 KiB echo | **934.5k** | — | 108.1k | 677.5k | 376.4k |
| 64 KiB response body | **42.5k** | — | 26.2k | 37.6k | 37.2k |
| 1 MiB response body | **4302** | — | 3018 | — | 3273 |
| 64 KiB static file | **43.3k** | — | 20.1k | 12.6k | 23.1k |
| 16 KiB text, gzip | **148.2k** | — | 32.7k | — | 33.5k |
| 16 KiB text, brotli | **122.6k** | — | — | 86.0k | — |
| Browser-like request headers | **1.01M** | — | 99.0k | 675.9k | 520.6k |
| Middleware chain | **1.83M** | — | 132.1k | 830.5k | 843.2k |

**The one row ALOS does not win:** plain HTTP/1.1 with a 64 KiB response body, where ntex is 6% ahead. ALOS uses less server CPU per response there (about 27 µs vs 31 µs). The gap comes from how fast the load generator's receive buffers grow on fresh connections in a short run. In 6-second runs the two tie (129.6k vs 129.2k).

**Allocations:** on HTTP/1.1, ALOS averages 0.005 heap allocations per request on `/plaintext` and about 1 per request on `/json`.

### How these were measured

- **Machine:** Intel Xeon E3-1270 v6 (4 cores / 8 threads), 31 GB RAM, Ubuntu 24.04.3, Linux 7.2.5, Go 1.26.9. Load generator and server run on the same machine over loopback, so they share the CPU.
- **Run shape:** 256 connections, 500 ms warm-up, 1.5 s measurement, 2 rounds interleaved across frameworks; the tables show the mean. `Connection: close` rows run last, and each framework starts only after the previous one's TIME_WAIT sockets have cleared.
- **Load generators:** `wrk` 4.1.0 (4 threads) for HTTP/1.1 and HTTPS; `h2load` (nghttp2 1.59.0, 4 threads, 100 streams per connection, 1 stream for the large-body, static and compression rows) for h2c and HTTP/2; a small custom tool for WebSocket.
- **TLS:** TLS 1.3; on HTTPS every framework negotiated TLS_AES_128_GCM_SHA256 with the same 16 KiB records.
- **Frameworks:** Fiber v3.6.1, gin v1.12.0, xitca-web 0.8.3, ntex 4.3.0.
- **Fairness:** every framework serves equivalent routes and payloads. The 64 KiB and 1 MiB bodies are prebuilt buffers sent without copying in every framework (`BytesNoCopy` in ALOS, `c.Send` in Fiber, `c.Data` in gin, a shared `Bytes` in xitca-web and ntex). Compression rows use each framework's own compression middleware at its default level.
- **Harness:** the test servers and scripts are in [`tests/perfcompare`](tests/perfcompare).

## Install

Linux only:

Add the module:

```bash
go get github.com/guno1928/alos-http@latest
```

Import the framework package:

```go
import "github.com/guno1928/alos-http/core"
```

If you want API documentation after publishing, the package docs will be available at:

https://alos.gg/aloshttpdocs/getting-started

## Quick Start

```go
package main

import (
    "log"
    "time"

    "github.com/guno1928/alos-http/core"
)

func main() {
    srv := core.New(core.Config{
        Addr:        ":8443",
        IdleTimeout: 120 * time.Second,
        ServerName:  "ALOS",
    })

    srv.Router.Use(core.Recovery())
    srv.Router.Use(core.RequestID())
    srv.Router.Use(core.SecurityHeaders(core.DefaultSecurityHeaders()))

    srv.Router.GET("/", func(req *core.Request, resp *core.Response) {
        resp.Status(200).String("ALOS HTTP is running")
    })

    srv.Router.GET("/users/:id", func(req *core.Request, resp *core.Response) {
        _ = resp.Status(200).JSONMarshal(map[string]any{
            "id":     req.ParamValue("id"),
            "method": req.Method,
            "path":   req.Path,
        })
    })

    log.Fatal(srv.ListenAndServeTLS())
}
```

## Plain HTTP Example

```go
srv := core.New(core.Config{
    Addr:      ":8080",
    PlainHTTP: true,
})

srv.Router.GET("/health", func(req *core.Request, resp *core.Response) {
    resp.Status(200).JSONString(`{"status":"ok"}`)
})

log.Fatal(srv.ListenAndServe())
```

## Middleware Example

```go
srv.Router.Use(core.Recovery())
srv.Router.Use(core.Logger())
srv.Router.Use(core.RealIP())
srv.Router.Use(core.RequestID())
srv.Router.Use(core.CORS(core.CORSConfig{
    AllowOrigins: []string{"*"},
    AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
}))
srv.Router.Use(core.Compress(core.CompressConfig{
    Level:       6,
    BrotliLevel: 4,
    MinSize:     512,
}))
```

Compression defaults to gzip level 2 and brotli level 4 when the levels are left at zero.

## Route Groups

```go
api := srv.Router.Group("/api", core.Logger())

api.GET("/status", func(req *core.Request, resp *core.Response) {
    resp.Status(200).JSONString(`{"status":"running"}`)
})

api.GET("/users/:id", func(req *core.Request, resp *core.Response) {
    resp.Status(200).String(req.ParamValue("id"))
})
```

## Reverse Proxy Example

```go
srv.SetProxy("api.example.com", core.DomainConfig{
    Backends: []core.BackendConfig{
        {Addr: "10.0.0.10:8080", Weight: 1},
        {Addr: "10.0.0.11:8080", Weight: 1},
    },
    LoadBalancer: core.LBRoundRobin,
    HealthCheck: core.HealthCheckConfig{
        Enabled:  true,
        Path:     "/health",
        Interval: 10 * time.Second,
        Timeout:  3 * time.Second,
    },
})
```

## Proxy Cache Example

```go
srv.SetProxyCache(core.ProxyCacheConfig{
    MaxEntrySize:   4 << 20,
    MaxTotalBytes:  256 << 20,
    DefaultMaxAge:  5 * time.Minute,
    CompressLevel:  6,
    CompressMinLen: 512,
    Rules: []core.CacheRule{
        {PathPrefix: "/static/", MaxAge: time.Hour},
        {PathPrefix: "/api/", MaxAge: 30 * time.Second, StatusOnly: []int{200}},
    },
})
```

## ACME Example

```go
srv := core.New(core.Config{
    Addr:          ":443",
    DefaultDomain: "example.com",
    ACME: &core.ACMEConfig{
        Email:   "admin@example.com",
        Domains: []string{"example.com", "www.example.com"},
    },
})

log.Fatal(srv.ListenAndServeTLS())
```

## Streaming and Files

```go
srv.Router.GET("/download", func(req *core.Request, resp *core.Response) {
    resp.SendFile(
        "./build/app.zip",
        core.WithAttachment("app.zip"),
        core.WithRateLimit(100),
    )
})
```

- Streamed responses (handlers that write through a `StreamWriter`, such as SSE, and proxied backend responses over 64 KiB or of unknown length) carry the server's CORS headers, but `OnResponse` hooks and `EnableCompress` compression are applied only to buffered responses.

## Status

ALOS HTTP is an actively developed framework with a strong focus on performance-sensitive serving, proxying, and low-level protocol control. API surface may continue to evolve while the project is being expanded.

## License

MIT, see [LICENSE](LICENSE). Copyright (c) 2026 guno1928.

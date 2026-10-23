//go:build linux && amd64

package core

import (
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// StaticConfig configures the file server returned by Static.
//
// Root is the filesystem directory whose contents are served; paths are resolved against it and confined to it.
//
//	Example: Root: "./public".
//	Example: Root: "/var/www/site".
//
// Index is the file served for directory requests; defaults to "index.html".
//
//	Example: Index: "index.html".
//	Example: Index: "home.html".
//
// Browse enables an HTML directory listing when a directory has no index file; defaults to false (such requests get 404).
//
//	Example: Browse: true.
//	Example: Browse: false.
//
// DisableCompression turns off the compressed copies Static otherwise serves; defaults to false. When compression is on, a cached text-like file (text/*, JavaScript, JSON, XML, SVG, WebAssembly, TTF/OTF fonts, ICO) between 256 bytes and CacheMaxFileSize is compressed once per cached file version in the background with brotli and gzip, stored in the file cache against CacheMaxBytes, and served to clients whose Accept-Encoding allows it with Vary: Accept-Encoding and a per-encoding ETag; requests that send Range always get the uncompressed file. Compression needs the file cache, so it is also off when DisableCache is set.
//
//	Example: DisableCompression: true.
//	Example: DisableCompression: false.
type StaticConfig struct {
	Root               string
	Index              string
	Browse             bool
	DisableCache       bool
	CacheMaxBytes      int64
	CacheMaxFileSize   int64
	CacheTTL           time.Duration
	DisableCompression bool
}

const wellKnownSegment = ".well-known"

func sanitizeStaticPath(p string) (string, bool) {
	if strings.ContainsAny(p, "\x00\\") {
		return "", false
	}
	if strings.Contains(p, "..") {
		return "", false
	}
	for i := 0; i < len(p); i++ {
		if p[i] != '.' || (i > 0 && p[i-1] != '/') {
			continue
		}
		seg := p[i:]
		if end := strings.IndexByte(seg, '/'); end >= 0 {
			seg = seg[:end]
		}
		if seg != wellKnownSegment {
			return "", false
		}
	}
	return p, true
}

func staticIndexIsPlainName(index string) bool {
	if strings.Contains(index, "/") {
		return false
	}
	_, ok := sanitizeStaticPath("/" + index)
	return ok
}

// Static returns a handler that serves files from cfg.Root under urlPrefix, stripping urlPrefix from the request path and rejecting traversal outside the root. Register it on a catch-all route so every path below the prefix reaches the handler.
//
// Example: s.Router.GET("/static/*filepath", Static("/static", StaticConfig{Root: "./public"}))
// Example: s.Router.GET("/files/*filepath", Static("/files", StaticConfig{Root: "/var/www", Browse: true}))
func Static(urlPrefix string, cfg StaticConfig) HandlerFunc {
	handler, _ := newStaticHandler(urlPrefix, cfg)
	return handler
}

func newStaticHandler(urlPrefix string, cfg StaticConfig) (HandlerFunc, *staticFileCache) {
	if !strings.HasPrefix(urlPrefix, "/") {
		urlPrefix = "/" + urlPrefix
	}
	urlPrefix = strings.TrimRight(urlPrefix, "/")

	if cfg.Index == "" {
		cfg.Index = "index.html"
	}

	absRoot, err := filepath.Abs(cfg.Root)
	if err != nil {
		absRoot = cfg.Root
	}
	root := newStaticRoot(absRoot)
	rootWithSep := absRoot
	if !strings.HasSuffix(rootWithSep, string(os.PathSeparator)) {
		rootWithSep += string(os.PathSeparator)
	}
	cache := newStaticFileCache(cfg)
	indexFast := !cfg.Browse && staticIndexIsPlainName(cfg.Index)

	handler := func(req *Request, resp *Response) {
		reqPath := strings.TrimPrefix(req.Path, urlPrefix)
		if reqPath == "" {
			reqPath = "/"
		}

		if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}

		cleanRel, ok := sanitizeStaticPath(reqPath)
		if !ok {
			resp.Status(400).String("Bad Request")
			return
		}

		cleanRel = strings.TrimPrefix(cleanRel, "/")
		fastRel := cleanRel
		if indexFast && (cleanRel == "" || strings.HasSuffix(cleanRel, "/")) {
			fastRel = cleanRel + cfg.Index
		}
		if fastRel != "" && root.serveFast(req, resp, fastRel, cache) {
			return
		}

		fullPath := filepath.Join(absRoot, filepath.FromSlash(cleanRel))

		absFullPath, err := filepath.Abs(fullPath)
		if err != nil {
			resp.Status(404).String("Not Found")
			return
		}

		if absFullPath != absRoot && !strings.HasPrefix(absFullPath, rootWithSep) {
			resp.Status(403).String("Forbidden")
			return
		}
		if status := root.contains(absFullPath); status != 0 {
			resp.Status(status).String(http.StatusText(status))
			return
		}

		info, err := os.Stat(absFullPath)
		if err != nil {
			resp.Status(404).String("Not Found")
			return
		}

		if info.IsDir() {
			indexPath := filepath.Join(absFullPath, cfg.Index)
			if root.contains(indexPath) == 0 && serveStaticFile(req, resp, indexPath) {
				return
			}

			if cfg.Browse {
				entries, err := os.ReadDir(absFullPath)
				if err != nil {
					resp.Status(500).String("Internal Server Error")
					return
				}
				dirURL := urlPrefix + "/" + cleanRel
				if !strings.HasSuffix(dirURL, "/") {
					dirURL += "/"
				}
				safeDir := html.EscapeString(dirURL)
				var b strings.Builder
				b.WriteString("<html><head><title>Index of ")
				b.WriteString(safeDir)
				b.WriteString("</title></head><body><h1>Index of ")
				b.WriteString(safeDir)
				b.WriteString("</h1><ul>")
				for _, entry := range entries {
					name := entry.Name()
					if _, listable := sanitizeStaticPath(name); !listable {
						continue
					}
					if entry.IsDir() {
						name += "/"
					}
					b.WriteString(fmt.Sprintf("<li><a href=\"%s\">%s</a></li>", html.EscapeString(dirURL+name), html.EscapeString(name)))
				}
				b.WriteString("</ul></body></html>")
				resp.Status(200).SetHeader("Content-Type", "text/html; charset=utf-8").SetBody([]byte(b.String()))
				return
			}

			resp.Status(404).String("Not Found")
			return
		}

		if !serveStaticFile(req, resp, absFullPath) {
			resp.Status(404).String("Not Found")
		}
	}
	return handler, cache
}

type staticRoot struct {
	abs       string
	absZ      []byte
	resolved  atomic.Pointer[staticRootDir]
	dir       atomic.Pointer[staticDirHandle]
	noOpenat2 atomic.Bool
}

type staticRootDir struct {
	dir        string
	dirWithSep string
}

func newStaticRoot(absRoot string) *staticRoot {
	root := &staticRoot{abs: absRoot, absZ: append([]byte(absRoot), 0)}
	root.resolved.Store(newStaticRootDir(evalStaticRoot(absRoot)))
	if strings.IndexByte(absRoot, 0) >= 0 {
		root.noOpenat2.Store(true)
	}
	return root
}

func evalStaticRoot(absRoot string) string {
	dir, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return absRoot
	}
	return dir
}

func newStaticRootDir(dir string) *staticRootDir {
	return &staticRootDir{dir: dir, dirWithSep: strings.TrimSuffix(dir, string(os.PathSeparator)) + string(os.PathSeparator)}
}

func (d *staticRootDir) holds(resolved string) bool {
	return resolved == d.dir || strings.HasPrefix(resolved, d.dirWithSep)
}

func (root *staticRoot) contains(path string) int {
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return http.StatusNotFound
	}
	if err != nil {
		return http.StatusForbidden
	}
	current := root.resolved.Load()
	if current.holds(resolved) {
		return 0
	}
	if dir := evalStaticRoot(root.abs); dir != current.dir {
		fresh := newStaticRootDir(dir)
		root.resolved.Store(fresh)
		if fresh.holds(resolved) {
			return 0
		}
	}
	return http.StatusForbidden
}

func serveStaticFile(req *Request, resp *Response, path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		return false
	}
	_ = resp.serveContent(req, f, fi, detectMIME(path), nil)
	return true
}

// StaticDir serves the directory root under urlPrefix using default StaticConfig; it is shorthand for Static(urlPrefix, StaticConfig{Root: root}).
//
// Example: s.Router.GET("/assets/*filepath", StaticDir("/assets", "./assets"))
// Example: s.Router.GET("/dl/*filepath", StaticDir("/dl", "/srv/downloads"))
func StaticDir(urlPrefix, root string) HandlerFunc {
	return Static(urlPrefix, StaticConfig{Root: root})
}

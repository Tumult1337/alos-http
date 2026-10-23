//go:build linux && amd64

package core

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/alosmap"
	"github.com/guno1928/turbo"
)

// SessionConfig configures the Sessions middleware.
//
// CookieName is the session cookie name; defaults to "alos_session" when empty.
//
//	Example: CookieName: "sid" stores the session id in a "sid" cookie.
//	Example: CookieName: "" uses the default "alos_session".
//
// MaxAge is the session and cookie lifetime in seconds; defaults to 86400 (one day) when zero.
//
//	Example: MaxAge: 3600 expires the session after one hour.
//	Example: MaxAge: 0 uses the default 86400.
//
// Secure emits the cookie with the Secure attribute, restricting it to HTTPS;
// sessions created on a TLS request are always emitted with Secure.
//
//	Example: Secure: true sends the cookie only over HTTPS.
//
// HttpOnly hides the cookie from client-side scripts; it is forced on.
//
//	Example: HttpOnly: true (the effective default) sets HttpOnly on the cookie.
//
// SameSite selects the cookie SameSite attribute; defaults to SameSiteLax when SameSiteDefault.
//
//	Example: SameSite: SameSiteStrict restricts the cookie to same-site requests.
//
// Path scopes the cookie path; defaults to "/" when empty.
//
//	Example: Path: "/app" scopes the session cookie to /app.
//
// Store is the backing session store; defaults to a new MemorySessionStore when nil.
//
//	Example: Store: NewMemorySessionStore() uses in-memory storage.
//	Example: Store: myCustomStore uses a custom SessionStore implementation.
type SessionConfig struct {
	CookieName string
	MaxAge     int
	Secure     bool
	HttpOnly   bool
	SameSite   SameSite
	Path       string
	Store      SessionStore
}

// SessionStore persists session data keyed by session id. Implement it to back sessions with a custom store.
//
// Get returns the data for id and whether it exists.
// Save persists data for id with a TTL of maxAge seconds (no expiry when maxAge <= 0).
// Delete removes the session for id.
type SessionStore interface {
	Get(id string) (map[string]any, bool)
	Save(id string, data map[string]any, maxAge int)
	Delete(id string)
}

// Session holds per-request session state retrieved with GetSession and persisted by the Sessions middleware when modified.
type Session struct {
	id       string
	data     map[string]any
	modified bool
	store    SessionStore
	maxAge   int
}

// Get returns the value stored under key and whether it was present.
//
// Example: v, ok := sess.Get("user_id")
// Example: if _, ok := sess.Get("csrf"); !ok { /* not set */ }
func (s *Session) Get(key string) (any, bool) {
	v, ok := s.data[key]
	return v, ok
}

// GetString returns the value stored under key as a string, or "" if absent or not a string.
//
// Example: name := sess.GetString("username")
// Example: if sess.GetString("role") == "admin" { /* ... */ }
func (s *Session) GetString(key string) string {
	v, ok := s.data[key]
	if !ok {
		return ""
	}
	str, _ := v.(string)
	return str
}

// Set stores value under key and marks the session modified so it is saved at the end of the request.
//
// Example: sess.Set("user_id", 42)
// Example: sess.Set("flash", "saved!")
func (s *Session) Set(key string, value any) {
	s.data[key] = value
	s.modified = true
}

// Delete removes key from the session and marks it modified.
//
// Example: sess.Delete("flash")
// Example: sess.Delete("user_id")
func (s *Session) Delete(key string) {
	delete(s.data, key)
	s.modified = true
}

// Clear removes all keys from the session and marks it modified.
func (s *Session) Clear() {
	for k := range s.data {
		delete(s.data, k)
	}
	s.modified = true
}

// ID returns the current session identifier.
func (s *Session) ID() string {
	return s.id
}

// Regenerate assigns a new session id, deleting the old entry from the store, and reports whether a new id was generated.
func (s *Session) Regenerate() bool {
	newID, ok := generateSessionID()
	if !ok {
		return false
	}
	if s.store != nil && s.id != "" {
		s.store.Delete(s.id)
	}
	s.id = newID
	s.modified = true
	return true
}

type sessionEntry struct {
	data      map[string]any
	expiresAt int64
	returned  atomic.Bool
}

type sessionEvictionCandidate struct {
	id    string
	entry *sessionEntry
}

// MemorySessionStore is an in-memory SessionStore suitable for single-process use.
// When it is full, a save first evicts sessions that no request has read back since they were
// created, soonest-expiring first, and then the soonest-expiring sessions that were read back.
type MemorySessionStore struct {
	entries       *alosmap.TypedMap[string, *sessionEntry]
	maxEntries    int64
	evictionBatch int64
	tracked       atomic.Int64
	evictMu       sync.Mutex
}

const (
	memorySessionDefaultMaxEntries    = 100_000
	memorySessionEvictionBatchDivisor = 8
	memorySessionNeverExpires         = math.MaxInt64
)

// NewMemorySessionStore returns an empty in-memory SessionStore.
func NewMemorySessionStore() *MemorySessionStore {
	return NewMemorySessionStoreWithMaxEntries(memorySessionDefaultMaxEntries)
}

func NewMemorySessionStoreWithMaxEntries(maxEntries int) *MemorySessionStore {
	if maxEntries <= 0 {
		maxEntries = memorySessionDefaultMaxEntries
	}
	return &MemorySessionStore{
		entries:       alosmap.NewTyped[string, *sessionEntry]().Prealloc(256),
		maxEntries:    int64(maxEntries),
		evictionBatch: max(1, int64(maxEntries)/memorySessionEvictionBatchDivisor),
	}
}

func (s *MemorySessionStore) reserveEntry() {
	for {
		n := s.tracked.Load()
		if n >= s.maxEntries {
			s.makeRoom()
			continue
		}
		if s.tracked.CompareAndSwap(n, n+1) {
			return
		}
	}
}

func (s *MemorySessionStore) makeRoom() {
	s.evictMu.Lock()
	defer s.evictMu.Unlock()
	if s.tracked.Load() < s.maxEntries {
		return
	}
	s.entries.CleanupNow()
	live := s.evictionCandidates()
	remaining := int64(len(live))
	if excess := remaining - (s.maxEntries - s.evictionBatch); excess > 0 {
		slices.SortFunc(live, compareSessionEviction)
		for _, victim := range live[:excess] {
			if s.entries.CompareAndDelete(victim.id, victim.entry) {
				remaining--
			}
		}
	}
	s.tracked.Store(remaining)
}

func compareSessionEviction(a, b sessionEvictionCandidate) int {
	if aReturned, bReturned := a.entry.returned.Load(), b.entry.returned.Load(); aReturned != bReturned {
		if aReturned {
			return 1
		}
		return -1
	}
	return cmp.Compare(a.entry.expiresAt, b.entry.expiresAt)
}

func (s *MemorySessionStore) evictionCandidates() []sessionEvictionCandidate {
	live := make([]sessionEvictionCandidate, 0, min(s.maxEntries, int64(s.entries.Len())))
	s.entries.Range(func(id string, entry *sessionEntry) bool {
		live = append(live, sessionEvictionCandidate{id: id, entry: entry})
		return true
	})
	return live
}

func sessionExpiresAt(ttl time.Duration) int64 {
	if ttl <= 0 {
		return memorySessionNeverExpires
	}
	return turbo.UnixNano() + int64(ttl)
}

// Get returns a copy of the stored session data for id, and whether it was found.
func (s *MemorySessionStore) Get(id string) (map[string]any, bool) {
	v, ok := s.entries.Load(id)
	if !ok {
		return nil, false
	}
	v.returned.Store(true)
	cp := make(map[string]any, len(v.data))
	for k, val := range v.data {
		cp[k] = val
	}
	return cp, true
}

// Save stores a copy of data under id, expiring it after maxAge seconds (no expiry when maxAge <= 0).
func (s *MemorySessionStore) Save(id string, data map[string]any, maxAge int) {
	s.saveWithTTL(id, data, time.Duration(maxAge)*time.Second)
}

func (s *MemorySessionStore) saveWithTTL(id string, data map[string]any, ttl time.Duration) {
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	entry := &sessionEntry{data: cp, expiresAt: sessionExpiresAt(ttl)}
	if old, ok := s.entries.Peek(id); ok {
		entry.returned.Store(old.returned.Load())
	} else {
		s.reserveEntry()
	}
	if ttl > 0 {
		s.entries.StoreWithTTL(id, entry, ttl)
	} else {
		s.entries.Store(id, entry)
	}
}

// Delete removes the stored session data for id.
func (s *MemorySessionStore) Delete(id string) {
	if _, ok := s.entries.Delete(id); ok {
		s.tracked.Add(-1)
	}
}

func generateSessionID() (string, bool) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	return hex.EncodeToString(b), true
}

// Sessions returns middleware that loads a session before the handler and saves it afterward when modified, applying cfg (see SessionConfig for per-field defaults).
//
// Example: app.Use(Sessions(SessionConfig{}))
// Example: app.Use(Sessions(SessionConfig{CookieName: "sid", MaxAge: 3600, Secure: true}))
// Example: app.Use(Sessions(SessionConfig{Store: NewMemorySessionStore()}))
func Sessions(cfg SessionConfig) MiddlewareFunc {
	if cfg.CookieName == "" {
		cfg.CookieName = "alos_session"
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 86400
	}
	if cfg.Path == "" {
		cfg.Path = "/"
	}
	if !cfg.HttpOnly {
		cfg.HttpOnly = true
	}
	if cfg.SameSite == SameSiteDefault {
		cfg.SameSite = SameSiteLax
	}
	if cfg.Store == nil {
		cfg.Store = NewMemorySessionStore()
	}

	cookieName := cfg.CookieName
	maxAge := cfg.MaxAge
	store := cfg.Store
	path := cfg.Path
	secure := cfg.Secure
	httpOnly := cfg.HttpOnly
	sameSite := cfg.SameSite

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, resp *Response) {
			sid := req.Cookie(cookieName)
			var data map[string]any

			if sid != "" {
				var ok bool
				data, ok = store.Get(sid)
				if !ok {
					var idOK bool
					sid, idOK = generateSessionID()
					if !idOK {
						resp.Status(500).String("internal error")
						return
					}
					data = make(map[string]any)
				}
			} else {
				var idOK bool
				sid, idOK = generateSessionID()
				if !idOK {
					resp.Status(500).String("internal error")
					return
				}
				data = make(map[string]any)
			}

			sess := &Session{
				id:       sid,
				data:     data,
				modified: false,
				store:    store,
				maxAge:   maxAge,
			}

			req.Set("session", sess)
			next(req, resp)

			if sess.modified {
				store.Save(sess.id, sess.data, maxAge)
				resp.SetCookie(Cookie{
					Name:     cookieName,
					Value:    sess.id,
					Path:     path,
					MaxAge:   maxAge,
					Secure:   secure || req.IsTLS,
					HttpOnly: httpOnly,
					SameSite: sameSite,
				})
			}
		}
	}
}

// GetSession returns the *Session attached to req by the Sessions middleware, or nil if none is present.
//
// Example: sess := GetSession(req); if sess == nil { return }
// Example: GetSession(req).Set("user_id", id)
func GetSession(req *Request) *Session {
	v, ok := req.Get("session")
	if !ok {
		return nil
	}
	sess, _ := v.(*Session)
	return sess
}

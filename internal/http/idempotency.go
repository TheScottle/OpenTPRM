package httpserver

import (
	"bytes"
	"net/http"
	"sync"
	"time"
)

// IdempotencyStore caches responses for Idempotency-Key (M5 contract).
type IdempotencyStore struct {
	mu   sync.Mutex
	byKey map[string]idemEntry
	ttl  time.Duration
}

type idemEntry struct {
	status  int
	headers http.Header
	body    []byte
	expires time.Time
}

func NewIdempotencyStore(ttl time.Duration) *IdempotencyStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &IdempotencyStore{byKey: map[string]idemEntry{}, ttl: ttl}
}

func (s *IdempotencyStore) get(key string, now time.Time) (idemEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byKey[key]
	if !ok || now.After(e.expires) {
		if ok {
			delete(s.byKey, key)
		}
		return idemEntry{}, false
	}
	return e, true
}

func (s *IdempotencyStore) put(key string, status int, headers http.Header, body []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make(http.Header, len(headers))
	for k, vv := range headers {
		cp[k] = append([]string(nil), vv...)
	}
	s.byKey[key] = idemEntry{
		status: status, headers: cp, body: append([]byte(nil), body...), expires: now.Add(s.ttl),
	}
}

type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
	hdr    http.Header
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	_, _ = c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

func (c *captureWriter) Header() http.Header {
	return c.ResponseWriter.Header()
}

// withIdempotency wraps a mutating handler when Idempotency-Key is present.
func (a *App) withIdempotency(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request)) {
	key := r.Header.Get("Idempotency-Key")
	if a.Idempotency == nil || key == "" || r.Method == http.MethodGet || r.Method == http.MethodHead {
		next(w, r)
		return
	}
	now := time.Now().UTC()
	if e, ok := a.Idempotency.get(key, now); ok {
		for k, vv := range e.headers {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Idempotent-Replay", "true")
		w.WriteHeader(e.status)
		_, _ = w.Write(e.body)
		return
	}
	cw := &captureWriter{ResponseWriter: w, status: 0}
	next(cw, r)
	status := cw.status
	if status == 0 {
		status = http.StatusOK
	}
	a.Idempotency.put(key, status, w.Header().Clone(), cw.buf.Bytes(), now)
}

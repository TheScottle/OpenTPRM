package httpserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestNFR_001_HealthReadyLatencySmoke is a vegeta-free httptest p95 smoke for /health/ready.
func TestNFR_001_HealthReadyLatencySmoke(t *testing.T) {
	app, h := testApp(t)
	_ = app
	const n = 50
	const workers = 10
	lat := make([]time.Duration, n)
	var wg sync.WaitGroup
	ch := make(chan int, n)
	for i := 0; i < n; i++ {
		ch <- i
	}
	close(ch)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				start := time.Now()
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
				lat[i] = time.Since(start)
				if rr.Code != http.StatusOK {
					t.Errorf("ready status %d", rr.Code)
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p95 := lat[(n*95)/100]
	// In-process smoke budget (NFR-001 reads ≤300ms at load; local httptest should be far lower).
	if p95 > 50*time.Millisecond {
		t.Fatalf("p95 /health/ready too slow: %v", p95)
	}
	t.Logf("NFR ready latency n=%d p50=%v p95=%v max=%v", n, lat[n/2], p95, lat[n-1])
}

// TestNFR_001_ConcurrentReadyAndAuthenticatedAPISmoke broadens NFR-001 with a
// concurrent /health/ready burst plus a separate authenticated API smoke.
func TestNFR_001_ConcurrentReadyAndAuthenticatedAPISmoke(t *testing.T) {
	_, h := testApp(t)
	const readyN = 40
	const workers = 8
	var readyFails atomic.Int32
	var wg sync.WaitGroup

	ch := make(chan int, readyN)
	for i := 0; i < readyN; i++ {
		ch <- i
	}
	close(ch)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range ch {
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
				if rr.Code != http.StatusOK {
					readyFails.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if readyFails.Load() != 0 {
		t.Fatalf("concurrent ready failures=%d", readyFails.Load())
	}

	// Authenticated API smoke (profile; avoids SQLite write storms after concurrent Ping).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("X-OpenTPRM-User", "analyst1")
	req.Header.Set("X-OpenTPRM-Roles", "risk_analyst")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("auth api smoke: %d %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("auth api body: %v %s", err, rr.Body.String())
	}
	if body["id"] != "analyst1" {
		t.Fatalf("auth api profile: %v", body)
	}
}

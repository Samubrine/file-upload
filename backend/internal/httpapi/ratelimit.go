package httpapi

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter is an in-memory token bucket keyed by an arbitrary string. The
// project runs as a single process, so per-process state is sufficient.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	now     func() time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

const (
	bucketIdleTTL   = 10 * time.Minute
	bucketSweepSize = 50000
)

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: map[string]*tokenBucket{}, now: time.Now}
}

// Allow spends one token from the bucket for key. The bucket holds up to
// capacity tokens and refills fully over the period. When the bucket is empty
// it returns false and how long until the next token is available.
func (l *rateLimiter) Allow(key string, capacity int, period time.Duration) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if len(l.buckets) > bucketSweepSize {
		for k, b := range l.buckets {
			if now.Sub(b.last) > bucketIdleTTL {
				delete(l.buckets, k)
			}
		}
	}

	rate := float64(capacity) / period.Seconds()
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: float64(capacity), last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(float64(capacity), b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / rate * float64(time.Second))
	return false, wait
}

// writeRateLimited sends a 429 response with a whole-second Retry-After header.
func writeRateLimited(w http.ResponseWriter, r *http.Request, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	WriteError(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "Too many attempts. Try again later.")
}

// clientIP returns the peer address without the port. Forwarded headers are
// ignored because no reverse proxy is part of this deployment.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

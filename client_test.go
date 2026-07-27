package mds

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appmds "github.com/go-ctap/mds/model"
	"github.com/google/uuid"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func statusTransport(status int) http.RoundTripper {
	return roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       http.NoBody,
			Header:     make(http.Header),
			Request:    request,
		}, nil
	})
}

func TestNewClientDefaultsMatchZeroValue(t *testing.T) {
	client := NewClient(nil)

	if client.source() != DefaultSource {
		t.Fatalf("source = %q, want %q", client.source(), DefaultSource)
	}
	if client.cache() != defaultCache {
		t.Fatal("cache does not use package-wide default")
	}
	if client.maxBlobBytes() != DefaultMaxBlobBytes {
		t.Fatalf("max blob bytes = %d, want %d", client.maxBlobBytes(), DefaultMaxBlobBytes)
	}
	if client.cacheDir() == "" {
		t.Fatal("default disk cache is disabled")
	}
}

func TestWithCacheDirControlsWrites(t *testing.T) {
	const source = "https://mds.example.test/cache-write"

	cacheDir := t.TempDir()
	client := NewClient(WithCacheDir(cacheDir))
	if _, err := client.storeDiskCache(source, []byte("jwt")); err != nil {
		t.Fatalf("store disk cache: %v", err)
	}
	path, err := client.diskCachePath(source)
	if err != nil {
		t.Fatalf("disk cache path: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read disk cache: %v", err)
	}
	if string(body) != "jwt" {
		t.Fatalf("disk cache body = %q, want %q", body, "jwt")
	}
}

func TestLookupRevalidationMarksDiskCacheFresh(t *testing.T) {
	const source = "https://mds.example.test/revalidation"

	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)

	client := &Client{
		Source:     source,
		HTTPClient: &http.Client{Transport: statusTransport(http.StatusNotModified)},
		Cache:      NewCache(),
		CacheDir:   t.TempDir(),
		Now:        func() time.Time { return now },
	}

	aaguid := uuid.New()
	client.Cache.Set(client.cacheKey(source), &Blob{
		Number:   1,
		Entries:  map[uuid.UUID]*appmds.PayloadEntry{},
		CachedAt: old,
	})

	path, err := client.diskCachePath(source)
	if err != nil {
		t.Fatalf("disk cache path: %v", err)
	}

	if err := os.WriteFile(path, []byte("cached"), 0o600); err != nil {
		t.Fatalf("write disk cache: %v", err)
	}

	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("age disk cache: %v", err)
	}

	if _, err := client.Lookup(context.Background(), aaguid, LookupOptions{}); err != nil {
		t.Fatalf("lookup: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat disk cache: %v", err)
	}

	if got := info.ModTime(); !got.Equal(now) {
		t.Fatalf("disk cache modtime = %v, want %v", got, now)
	}
}

func TestLookupAllowsVerifiedStaleCacheOnRateLimit(t *testing.T) {
	const source = "https://mds.example.test/rate-limit"

	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	var fetches atomic.Int64
	client := &Client{
		Source:   source,
		Cache:    NewCache(),
		CacheDir: t.TempDir(),
		Now:      func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			fetches.Add(1)
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       http.NoBody,
				Header:     make(http.Header),
				Request:    request,
			}, nil
		})},
	}

	aaguid := uuid.New()
	client.Cache.Set(client.cacheKey(source), &Blob{
		Number:   1,
		Entries:  map[uuid.UUID]*appmds.PayloadEntry{},
		CachedAt: now.Add(-48 * time.Hour),
	})

	result, err := client.Lookup(context.Background(), aaguid, LookupOptions{})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if !result.Cached {
		t.Fatal("lookup did not report the verified cache")
	}

	if _, err := client.Lookup(context.Background(), aaguid, LookupOptions{Refresh: true}); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 during minimum request delay", got)
	}

	now = now.Add(time.Hour)
	if _, err := client.Lookup(context.Background(), aaguid, LookupOptions{Refresh: true}); err != nil {
		t.Fatalf("lookup after minimum delay: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetches = %d, want 2 after minimum request delay", got)
	}
}

func TestLookupDoesNotMaskContextErrorWithStaleCache(t *testing.T) {
	tests := []struct {
		name    string
		context func() (context.Context, context.CancelFunc)
		want    error
	}{
		{
			name: "canceled",
			context: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				return ctx, func() {}
			},
			want: context.Canceled,
		},
		{
			name: "deadline",
			context: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const source = "https://mds.example.test/context-error"

			cache := NewCache()
			client := &Client{
				Source: source,
				Cache:  cache,
			}
			cache.Set(client.cacheKey(source), &Blob{
				Number:   1,
				Entries:  map[uuid.UUID]*appmds.PayloadEntry{},
				CachedAt: time.Now().Add(-48 * time.Hour),
			})
			ctx, cancel := test.context()
			defer cancel()

			_, err := client.Lookup(ctx, uuid.New(), LookupOptions{Refresh: true})

			if !errors.Is(err, test.want) {
				t.Fatalf("Lookup error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLookupSharesCachedEntry(t *testing.T) {
	const source = "https://mds.example.test/shared-entry"

	aaguid := uuid.New()
	entry := &appmds.PayloadEntry{
		AAGUID: aaguid,
		MetadataStatement: appmds.MetadataStatement{
			FriendlyNames: map[string]string{"en": "Original"},
		},
	}

	client := &Client{
		Source: source,
		Cache:  NewCache(),
	}

	client.Cache.Set(client.cacheKey(source), &Blob{
		Number:   1,
		Entries:  map[uuid.UUID]*appmds.PayloadEntry{aaguid: entry},
		CachedAt: time.Now(),
	})

	result, err := client.Lookup(context.Background(), aaguid, LookupOptions{})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}

	if result.Entry != entry {
		t.Fatalf("entry pointer = %p, want cached pointer %p", result.Entry, entry)
	}

	result.Entry.MetadataStatement.FriendlyNames["en"] = "Updated"
	if entry.MetadataStatement.FriendlyNames["en"] != "Updated" {
		t.Fatalf("cached entry = %#v, want shared update", entry)
	}
}

func TestLookupKeepsDiskCacheWhenVerificationFails(t *testing.T) {
	const source = "https://mds.example.test/invalid-cache"

	client := &Client{
		Source:     source,
		HTTPClient: &http.Client{Transport: statusTransport(http.StatusServiceUnavailable)},
		Cache:      NewCache(),
		CacheDir:   t.TempDir(),
	}

	path, err := client.diskCachePath(source)
	if err != nil {
		t.Fatalf("disk cache path: %v", err)
	}

	cached := []byte("cached blob awaiting successful revalidation")
	if err := os.WriteFile(path, cached, 0o600); err != nil {
		t.Fatalf("write disk cache: %v", err)
	}

	_, err = client.Lookup(context.Background(), uuid.New(), LookupOptions{})
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("lookup error = %v, want %v", err, ErrFetch)
	}

	retained, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read retained disk cache: %v", err)
	}

	if !bytes.Equal(retained, cached) {
		t.Fatalf("retained disk cache = %q, want %q", retained, cached)
	}
}

func TestLookupKeepsVerifiedMemoryCacheWhenRemoteVerificationFails(t *testing.T) {
	const source = "https://mds.example.test/unverifiable-remote"

	aaguid := uuid.New()
	entry := &appmds.PayloadEntry{
		AAGUID: aaguid,
		MetadataStatement: appmds.MetadataStatement{
			Description: "Verified local authenticator",
		},
	}
	local := &Blob{
		Number:   7,
		Entries:  map[uuid.UUID]*appmds.PayloadEntry{aaguid: entry},
		CachedAt: time.Now().Add(-48 * time.Hour),
	}
	cache := NewCache()
	client := &Client{
		Source: source,
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not-a-jwt")),
				Request:    request,
			}, nil
		})},
		Cache: cache,
	}
	cacheKey := client.cacheKey(source)
	cache.Set(cacheKey, local)

	result, err := client.Lookup(t.Context(), aaguid, LookupOptions{Refresh: true})
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !result.Cached || result.Entry != entry || result.BlobNumber != local.Number {
		t.Fatalf("result = %+v, want verified local entry", result)
	}
	cached, found := cache.Get(cacheKey)
	if !found || cached.Number != local.Number || cached.Entries[aaguid] != entry {
		t.Fatalf("cached blob = %#v, %t; want verified local data", cached, found)
	}
	if !cached.CachedAt.After(local.CachedAt) {
		t.Fatalf("CachedAt = %v, want value after %v", cached.CachedAt, local.CachedAt)
	}
}

func TestLookupCoordinatesRefreshByCacheKey(t *testing.T) {
	const callers = 8

	cache := NewCache().(*simpleCache)
	source := "https://mds.example.test/concurrent"
	release := make(chan struct{})
	started := make(chan struct{})
	var startOnce sync.Once
	var fetches atomic.Int64
	client := &Client{
		Source:   source,
		Cache:    cache,
		CacheDir: t.TempDir(),
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			fetches.Add(1)
			startOnce.Do(func() { close(started) })
			<-release

			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    request,
			}, nil
		})},
	}

	begin := make(chan struct{})
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-begin
			_, err := client.Lookup(t.Context(), uuid.New(), LookupOptions{})
			errs <- err
		}()
	}

	ready.Wait()
	close(begin)
	<-started
	waitForRefreshWaiters(t, cache, client.cacheKey(source), callers)
	close(release)

	for range callers {
		if err := <-errs; !errors.Is(err, ErrFetch) {
			t.Fatalf("Lookup error = %v, want %v", err, ErrFetch)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1", got)
	}
}

func waitForRefreshWaiters(t *testing.T, cache *simpleCache, key string, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		cache.mu.RLock()
		call := cache.refresh[key]
		got := 0
		if call != nil {
			got = call.waiters
		}
		cache.mu.RUnlock()

		if got == want {
			return
		}
		runtime.Gosched()
	}

	t.Fatalf("refresh waiters did not reach %d", want)
}

func TestBlobFetchRejectsRedirectAndOversizeResponse(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		maxBytes   int64
		wantStatus int
		wantText   string
	}{
		{name: "redirect", status: http.StatusFound, wantStatus: http.StatusFound},
		{name: "oversize", status: http.StatusOK, body: "1234", maxBytes: 3, wantText: "object exceeds 3 bytes"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{
				Source:       "https://mds.example.test/blob",
				MaxBlobBytes: test.maxBytes,
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: test.status,
						Header:     http.Header{"Location": {"https://mds.example.test/redirected"}},
						Body:       io.NopCloser(strings.NewReader(test.body)),
						Request:    request,
					}, nil
				})},
			}

			_, _, _, err := client.fetchAndVerify(t.Context(), client.Source, nil)
			if test.wantStatus != 0 {
				var statusErr *HTTPStatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != test.wantStatus {
					t.Fatalf("fetchAndVerify error = %v, want HTTP status %d", err, test.wantStatus)
				}
				return
			}

			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("fetchAndVerify error = %v, want %q", err, test.wantText)
			}
		})
	}
}

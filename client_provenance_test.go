package mds

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/telesma-app/mds/model"
)

func TestLookupCacheProvenance(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		age     time.Duration
		refresh bool
		found   bool
		fetches int
	}{
		{name: "cache hit", age: time.Minute, found: true},
		{name: "no entry", age: time.Minute},
		{name: "throttled", age: time.Hour - time.Nanosecond, refresh: true, found: true},
		{name: "explicit refresh", age: time.Hour, refresh: true, found: true, fetches: 1},
		{name: "automatic refresh", age: DefaultRefreshInterval, found: true, fetches: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			fetches := 0
			client := &Client{
				Source:   "https://mds.example.test/cache-provenance",
				Cache:    NewCache(),
				CacheDir: t.TempDir(),
				Now:      func() time.Time { return now },
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					fetches++
					return statusTransport(http.StatusNotModified).RoundTrip(request)
				})},
			}
			aaguid := uuid.New()
			local := &Blob{Number: 7, CheckedAt: now.Add(-test.age), Entries: map[uuid.UUID]*model.PayloadEntry{}}
			if test.found {
				local.Entries[aaguid] = &model.PayloadEntry{AAGUID: aaguid}
			}
			client.Cache.Set(client.cacheKey(client.Source), local)

			result, err := client.Lookup(t.Context(), aaguid, LookupOptions{Refresh: test.refresh})
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if result.AAGUID != aaguid || result.Source != client.Source || result.BlobNumber != local.Number || !result.Cached {
				t.Fatalf("provenance = %+v", result)
			}
			if result.Found != test.found || result.Entry != local.Entries[aaguid] {
				t.Fatalf("entry = %+v, found = %t", result.Entry, result.Found)
			}
			if result.RefreshErr != nil || fetches != test.fetches {
				t.Fatalf("refresh error = %v, fetches = %d; want %d", result.RefreshErr, fetches, test.fetches)
			}
			checkedAt := local.CheckedAt
			if test.fetches > 0 {
				checkedAt = now
			}
			if !result.CheckedAt.Equal(checkedAt) {
				t.Fatalf("CheckedAt = %v, want %v", result.CheckedAt, checkedAt)
			}
			if !local.CheckedAt.Equal(now.Add(-test.age)) {
				t.Fatal("refresh mutated an existing cache snapshot")
			}
		})
	}
}

func TestLookupSignedRefresh(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	key := assessmentKey(t)
	root := assessmentCertificate(t, key, nil, key, true, now)
	aaguid := uuid.New()
	for _, test := range []struct {
		name   string
		local  uint64
		remote uint64
		found  bool
		cached bool
		failed bool
	}{
		{name: "first retrieval", remote: 8, found: true},
		{name: "newer blob", local: 7, remote: 8, found: true},
		{name: "no entry", remote: 8},
		{name: "same serial", local: 7, remote: 7, found: true, cached: true},
		{name: "rollback", local: 7, remote: 6, found: true, cached: true, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			entries := []model.PayloadEntry{}
			if test.found {
				entries = append(entries, model.PayloadEntry{AAGUID: aaguid, MetadataStatement: model.MetadataStatement{Description: "remote"}})
			}
			raw := signedLookupBlob(t, key, test.remote, entries)
			client := &Client{
				Source:       "https://mds.example.test/signed-refresh",
				Cache:        NewCache(),
				CacheDir:     t.TempDir(),
				TrustAnchors: []*x509.Certificate{root},
				Now:          func() time.Time { return now },
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(raw)), Request: request}, nil
				})},
			}
			old := now.Add(-48 * time.Hour)
			localEntry := &model.PayloadEntry{AAGUID: aaguid, MetadataStatement: model.MetadataStatement{Description: "local"}}
			if test.local != 0 {
				client.Cache.Set(client.cacheKey(client.Source), &Blob{Number: test.local, Entries: map[uuid.UUID]*model.PayloadEntry{aaguid: localEntry}, CheckedAt: old})
				if err := client.storeDiskCache(client.Source, []byte("previous disk contents"), old); err != nil {
					t.Fatal(err)
				}
			}
			result, err := client.Lookup(t.Context(), aaguid, LookupOptions{Refresh: true})
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if result.Found != test.found || result.AAGUID != aaguid || result.Source != client.Source {
				t.Fatalf("provenance = %+v", result)
			}
			wantNumber, wantCheckedAt := test.remote, now
			if test.failed {
				wantNumber, wantCheckedAt = test.local, old
				if !errors.Is(result.RefreshErr, ErrVerify) {
					t.Fatalf("refresh error = %v, want ErrVerify", result.RefreshErr)
				}
			} else if result.RefreshErr != nil {
				t.Fatalf("refresh error = %v", result.RefreshErr)
			}
			if result.BlobNumber != wantNumber || !result.CheckedAt.Equal(wantCheckedAt) || result.Cached != test.cached {
				t.Fatalf("blob provenance = %+v", result)
			}
			path, err := client.diskCachePath(client.Source)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || !info.ModTime().Equal(wantCheckedAt) {
				t.Fatalf("disk timestamp = %v, err = %v; want %v", info, err, wantCheckedAt)
			}
			if result.Cached {
				if result.Entry != localEntry {
					t.Fatal("cached entry was replaced")
				}
				body, err := os.ReadFile(path)
				if err != nil || string(body) != "previous disk contents" {
					t.Fatalf("cached disk contents changed: %q, %v", body, err)
				}
			} else {
				loaded, serial := client.loadDiskCache(t.Context(), client.Source)
				if loaded == nil || serial != test.remote || !loaded.CheckedAt.Equal(now) {
					t.Fatalf("reloaded cache = %+v, serial = %d", loaded, serial)
				}
				if test.found && result.Entry.MetadataStatement.Description != "remote" {
					t.Fatalf("entry = %+v, want remote", result.Entry)
				}
				if !test.found && result.Entry != nil {
					t.Fatalf("entry = %+v, want nil", result.Entry)
				}
			}
		})
	}
}

func TestLookupRefreshFailureProvenance(t *testing.T) {
	networkErr := errors.New("network unavailable")
	for _, failure := range []struct {
		name      string
		transport http.RoundTripper
		want      error
	}{
		{name: "network", transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, networkErr }), want: ErrFetch},
		{name: "request timeout", transport: roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, context.DeadlineExceeded }), want: ErrFetch},
		{name: "HTTP error", transport: statusTransport(http.StatusServiceUnavailable), want: ErrFetch},
		{name: "verification", transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("not-a-jwt")), Request: request}, nil
		}), want: ErrVerify},
	} {
		for _, withCache := range []bool{false, true} {
			name := failure.name + "/without cache"
			if withCache {
				name = failure.name + "/with cache"
			}
			t.Run(name, func(t *testing.T) {
				now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
				old := now.Add(-48 * time.Hour)
				aaguid := uuid.New()
				entry := &model.PayloadEntry{AAGUID: aaguid}
				fetches := 0
				client := &Client{
					Source:   "https://mds.example.test/failure",
					Cache:    NewCache(),
					CacheDir: t.TempDir(),
					Now:      func() time.Time { return now },
					HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
						fetches++
						return failure.transport.RoundTrip(request)
					})},
				}
				if withCache {
					client.Cache.Set(client.cacheKey(client.Source), &Blob{Number: 7, Entries: map[uuid.UUID]*model.PayloadEntry{aaguid: entry}, CheckedAt: old})
					if err := client.storeDiskCache(client.Source, []byte("cached contents"), old); err != nil {
						t.Fatal(err)
					}
				}
				result, err := client.Lookup(t.Context(), aaguid, LookupOptions{})
				if !withCache {
					if !errors.Is(err, failure.want) || result.Entry != nil {
						t.Fatalf("result = %+v, err = %v; want %v", result, err, failure.want)
					}
					return
				}
				if err != nil || !errors.Is(result.RefreshErr, failure.want) {
					t.Fatalf("refresh = %+v, err = %v", result.RefreshErr, err)
				}
				if !result.Cached || !result.Found || result.Entry != entry || result.BlobNumber != 7 || result.AAGUID != aaguid || result.Source != client.Source {
					t.Fatalf("cached provenance = %+v", result)
				}
				if !result.CheckedAt.Equal(old) {
					t.Fatalf("timestamps = %+v", result)
				}
				previousError := result.RefreshErr
				if failure.name == "HTTP error" {
					status, ok := errors.AsType[*HTTPStatusError](result.RefreshErr)
					if !ok || status.StatusCode != http.StatusServiceUnavailable {
						t.Fatalf("refresh error = %v, want HTTP 503", result.RefreshErr)
					}
				}
				assertLookupJSON(t, result)
				for _, refresh := range []bool{false, true} {
					skipped, err := client.Lookup(t.Context(), aaguid, LookupOptions{Refresh: refresh})
					if err != nil || skipped.RefreshErr != previousError || !skipped.CheckedAt.Equal(old) {
						t.Fatalf("skipped lookup = %+v, err = %v", skipped, err)
					}
					assertLookupJSON(t, skipped)
				}
				if fetches != 1 {
					t.Fatalf("fetches = %d, want 1", fetches)
				}
				path, err := client.diskCachePath(client.Source)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil || !info.ModTime().Equal(old) {
					t.Fatalf("disk timestamp changed: %v, %v", info, err)
				}
				body, err := os.ReadFile(path)
				if err != nil || string(body) != "cached contents" {
					t.Fatalf("disk contents changed: %q, %v", body, err)
				}

				// A later successful revalidation clears the error and advances
				// the successful check time, independently of the previous attempt.
				now = now.Add(minRequestDelay)
				client.HTTPClient.Transport = statusTransport(http.StatusNotModified)
				recovered, err := client.Lookup(t.Context(), aaguid, LookupOptions{Refresh: true})
				if err != nil || recovered.RefreshErr != nil || !recovered.CheckedAt.Equal(now) {
					t.Fatalf("recovered lookup = %+v, err = %v", recovered, err)
				}
			})
		}
	}
}

func assertLookupJSON(t *testing.T, result model.LookupResult) {
	t.Helper()
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["refresh"]; ok {
		t.Fatal("lookup serializes refresh details")
	}
	if _, ok := fields["RefreshErr"]; ok {
		t.Fatal("lookup serializes the Go error")
	}
	var decoded model.LookupResult
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RefreshErr != nil || !decoded.CheckedAt.Equal(result.CheckedAt) || decoded.Found != result.Found {
		t.Fatalf("decoded lookup = %+v", decoded)
	}
}

func signedLookupBlob(t *testing.T, key *ecdsa.PrivateKey, number uint64, entries []model.PayloadEntry) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"no": number, "entries": entries})
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign BLOB: %v", err)
	}
	return raw
}

func TestLookupVerifiedDiskCacheProvenance(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	old := now.Add(-30 * time.Minute)
	key := assessmentKey(t)
	root := assessmentCertificate(t, key, nil, key, true, now)
	aaguid := uuid.New()
	raw := signedLookupBlob(t, key, 7, []model.PayloadEntry{{AAGUID: aaguid}})
	fetches := 0
	client := &Client{
		Source:       "https://mds.example.test/disk-provenance",
		Cache:        NewCache(),
		CacheDir:     t.TempDir(),
		TrustAnchors: []*x509.Certificate{root},
		Now:          func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			fetches++
			return statusTransport(http.StatusServiceUnavailable).RoundTrip(request)
		})},
	}
	if err := client.storeDiskCache(client.Source, []byte(raw), old); err != nil {
		t.Fatal(err)
	}
	result, err := client.Lookup(t.Context(), aaguid, LookupOptions{})
	if err != nil || !result.Cached || !result.Found || result.BlobNumber != 7 || !result.CheckedAt.Equal(old) || result.RefreshErr != nil || fetches != 0 {
		t.Fatalf("disk lookup = %+v, err = %v, fetches = %d", result, err, fetches)
	}

	now = now.Add(48 * time.Hour)
	// A new process can verify the signed disk cache again without changing the
	// time of the last successful network check, even if refresh now fails.
	client.Cache = NewCache()
	result, err = client.Lookup(t.Context(), aaguid, LookupOptions{})
	if err != nil || !result.Cached || !result.Found || !result.CheckedAt.Equal(old) || !errors.Is(result.RefreshErr, ErrFetch) || fetches != 1 {
		t.Fatalf("stale disk lookup = %+v, err = %v, fetches = %d", result, err, fetches)
	}
	path, err := client.diskCachePath(client.Source)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.ModTime().Equal(old) {
		t.Fatalf("disk timestamp changed: %v, %v", info, err)
	}
}

func TestLookupCancellationDoesNotChangeCache(t *testing.T) {
	for _, test := range []struct {
		name      string
		withCache bool
	}{
		{name: "canceled during refresh with cache", withCache: true},
		{name: "canceled during refresh without cache"},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			fetches := 0
			client := &Client{
				Source:   "https://mds.example.test/cancel",
				Cache:    NewCache(),
				CacheDir: t.TempDir(),
				Now:      func() time.Time { return now },
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					fetches++
					cancel()
					return nil, request.Context().Err()
				})},
			}
			local := &Blob{Number: 7, CheckedAt: now.Add(-48 * time.Hour)}
			cacheKey := client.cacheKey(client.Source)
			if test.withCache {
				client.Cache.Set(cacheKey, local)
			}
			_, err := client.Lookup(ctx, uuid.New(), LookupOptions{})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Lookup error = %v, want cancellation", err)
			}
			if fetches != 1 {
				t.Fatalf("fetches = %d", fetches)
			}
			cached, found := client.Cache.Get(cacheKey)
			if found != test.withCache || found && cached != local {
				t.Fatalf("canceled lookup changed cache: %+v, %t", cached, found)
			}
		})
	}
}

func TestLookupWaiterCancellation(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	started, release := make(chan struct{}), make(chan struct{})
	cache := NewCache().(*simpleCache)
	client := &Client{
		Source:   "https://mds.example.test/waiter-cancellation",
		Cache:    cache,
		CacheDir: t.TempDir(),
		Now:      func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			close(started)
			<-release
			return statusTransport(http.StatusNotModified).RoundTrip(request)
		})},
	}
	cacheKey := client.cacheKey(client.Source)
	local := &Blob{Number: 7, CheckedAt: now.Add(-48 * time.Hour)}
	cache.Set(cacheKey, local)
	aaguid := uuid.New()
	ownerResult := make(chan model.LookupResult, 1)
	ownerErr := make(chan error, 1)
	go func() {
		result, err := client.Lookup(t.Context(), aaguid, LookupOptions{})
		ownerResult <- result
		ownerErr <- err
	}()
	<-started
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waiterErr := make(chan error, 1)
	go func() {
		_, err := client.Lookup(ctx, aaguid, LookupOptions{})
		waiterErr <- err
	}()
	waitForRefreshWaiters(t, cache, cacheKey, 2)
	cancel()
	if err := <-waiterErr; !errors.Is(err, context.Canceled) {
		t.Errorf("waiter error = %v, want cancellation", err)
	}
	cached, _ := cache.Get(cacheKey)
	if cached != local {
		t.Error("canceled waiter changed the cache")
	}
	close(release)
	if err := <-ownerErr; err != nil {
		t.Fatalf("owner error = %v", err)
	}
	if result := <-ownerResult; result.RefreshErr != nil || !result.CheckedAt.Equal(now) {
		t.Fatalf("owner result = %+v", result)
	}
}

func TestLookupSharesRefreshFailureWithCache(t *testing.T) {
	const callers = 8
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	cache := NewCache().(*simpleCache)
	release := make(chan struct{})
	client := &Client{
		Source:   "https://mds.example.test/shared-failure",
		Cache:    cache,
		CacheDir: t.TempDir(),
		Now:      func() time.Time { return now },
		HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			<-release
			return statusTransport(http.StatusServiceUnavailable).RoundTrip(request)
		})},
	}
	aaguid := uuid.New()
	entry := &model.PayloadEntry{AAGUID: aaguid}
	local := &Blob{Number: 7, CheckedAt: now.Add(-48 * time.Hour), Entries: map[uuid.UUID]*model.PayloadEntry{aaguid: entry}}
	cacheKey := client.cacheKey(client.Source)
	cache.Set(cacheKey, local)
	results := make(chan model.LookupResult, callers)
	errs := make(chan error, callers)
	for range callers {
		go func() {
			result, err := client.Lookup(t.Context(), aaguid, LookupOptions{Refresh: true})
			results <- result
			errs <- err
		}()
	}
	waitForRefreshWaiters(t, cache, cacheKey, callers)
	close(release)
	var sharedError error
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("Lookup error = %v", err)
		}
		result := <-results
		if !result.Cached || !result.Found || result.Entry != entry || !result.CheckedAt.Equal(local.CheckedAt) || !errors.Is(result.RefreshErr, ErrFetch) {
			t.Fatalf("shared result = %+v", result)
		}
		if sharedError != nil && sharedError != result.RefreshErr {
			t.Fatal("waiters did not observe the same refresh failure")
		}
		sharedError = result.RefreshErr
	}
}

func TestLookupCheckedAtTracksSuccessfulCompletion(t *testing.T) {
	for _, succeeds := range []bool{false, true} {
		name := "failed"
		if succeeds {
			name = "revalidated"
		}
		t.Run(name, func(t *testing.T) {
			started := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
			completed := started.Add(2 * time.Minute)
			now := started
			old := started.Add(-48 * time.Hour)
			client := &Client{
				Source:   "https://mds.example.test/check-times",
				Cache:    NewCache(),
				CacheDir: t.TempDir(),
				Now:      func() time.Time { return now },
				HTTPClient: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
					now = completed
					status := http.StatusServiceUnavailable
					if succeeds {
						status = http.StatusNotModified
					}
					return statusTransport(status).RoundTrip(request)
				})},
			}
			client.Cache.Set(client.cacheKey(client.Source), &Blob{Number: 7, CheckedAt: old})
			result, err := client.Lookup(t.Context(), uuid.New(), LookupOptions{})
			if err != nil {
				t.Fatal(err)
			}
			checkedAt := old
			if succeeds {
				checkedAt = completed
			}
			if !result.CheckedAt.Equal(checkedAt) {
				t.Fatalf("CheckedAt = %v, want %v", result.CheckedAt, checkedAt)
			}
		})
	}
}

package mds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ctap/mds/internal/mdsverify"
	appmds "github.com/go-ctap/mds/model"
	"github.com/google/uuid"
)

const (
	DefaultSource          = "https://mds.fidoalliance.org/"
	DefaultRefreshInterval = 24 * time.Hour
	DefaultMaxBlobBytes    = 64 << 20 // 64 MiB

	minRequestDelay = time.Hour
	cacheNamespace  = "go-ctap"
	cacheDirName    = "mds"
)

var (
	ErrInvalidAAGUID = errors.New("invalid AAGUID")
	ErrFetch         = errors.New("fetch MDS blob")
	ErrVerify        = errors.New("verify MDS blob")

	defaultCache = NewCache()
)

// HTTPStatusError reports a non-success response from the configured MDS endpoint.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("%s: HTTP status %d", ErrFetch, e.StatusCode)
}

func (e *HTTPStatusError) Unwrap() error {
	return ErrFetch
}

// Client fetches, caches, and looks up verified FIDO Metadata Service blobs.
// Signature, x5u/x5c, certificate-chain and CRL validation live in internal/mdsverify.
type Client struct {
	Source       string
	HTTPClient   *http.Client
	Cache        Cache
	CacheDir     string
	TrustAnchors []*x509.Certificate

	// MaxBlobBytes bounds metadata BLOB downloads. Zero means DefaultMaxBlobBytes.
	MaxBlobBytes int64

	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// LookupOptions configures one MDS lookup.
type LookupOptions struct {
	// Refresh forces a conditional network refresh attempt, but still loads the
	// local copy first so localCopySerial and anti-rollback checks keep working.
	Refresh bool
}

// Blob is a verified and indexed MDS payload.
// Treat it as immutable after storing it in Cache.
type Blob struct {
	Number uint64

	// IssuedAt is best-effort metadata. It is read from the MDS JWT header iat
	// when present, otherwise from the standard payload iat parsed by
	// jwt.RegisteredClaims. It is zero when both are absent.
	IssuedAt time.Time

	Entries map[uuid.UUID]*appmds.PayloadEntry

	CachedAt time.Time
}

// Lookup returns verified MDS data for one AAGUID.
func (c *Client) Lookup(ctx context.Context, aaguid uuid.UUID, opts LookupOptions) (appmds.LookupResult, error) {
	if aaguid == uuid.Nil {
		return appmds.LookupResult{}, ErrInvalidAAGUID
	}

	source := c.source()
	blob, cached, err := c.blob(ctx, source, opts)
	if err != nil {
		return appmds.LookupResult{}, err
	}

	entry, found := blob.Entries[aaguid]
	result := appmds.LookupResult{
		AAGUID:     aaguid,
		Found:      found,
		BlobNumber: blob.Number,
		Source:     source,
		Cached:     cached,
		CachedAt:   blob.CachedAt,
	}

	if found {
		result.Entry = entry
	}

	return result, nil
}

func (c *Client) blob(ctx context.Context, source string, opts LookupOptions) (*Blob, bool, error) {
	cacheKey := c.cacheKey(source)
	local := c.loadLocal(ctx, source, cacheKey)
	if local != nil && !c.shouldRefresh(local, opts) {
		return local, true, nil
	}

	refreshed, cached, err := c.cache().Refresh(ctx, cacheKey, func() (*Blob, bool, error) {
		current := c.loadLocal(ctx, source, cacheKey)
		if current != nil && !opts.Refresh && !c.shouldRefresh(current, opts) {
			return current, true, nil
		}

		return c.refreshBlob(ctx, source, cacheKey, current)
	})
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, false, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, false, err
		}
		if local != nil {
			return c.markLocalFresh(source, cacheKey, local), true, nil
		}
	}

	return refreshed, cached, err
}

func (c *Client) refreshBlob(ctx context.Context, source, cacheKey string, local *Blob) (*Blob, bool, error) {
	remote, raw, notModified, err := c.fetchAndVerify(ctx, source, local)
	if err != nil {
		return nil, false, err
	}

	if notModified {
		if local == nil {
			return nil, false, fmt.Errorf("%w: server returned 304 without a local blob", ErrFetch)
		}

		return c.markLocalFresh(source, cacheKey, local), true, nil
	}

	if local != nil && remote.Number == local.Number {
		return c.markLocalFresh(source, cacheKey, local), true, nil
	}

	if local != nil && remote.Number < local.Number {
		return c.markLocalFresh(source, cacheKey, local), true, nil
	}

	cachedAt, err := c.storeDiskCache(source, raw)
	if err != nil {
		cachedAt = c.now()
	} else if cachedAt.IsZero() {
		cachedAt = c.now()
	}
	remote.CachedAt = cachedAt

	c.cache().Set(cacheKey, remote)
	return remote, false, nil
}

func (c *Client) markLocalFresh(source, cacheKey string, local *Blob) *Blob {
	refreshed := *local
	refreshed.CachedAt = c.now()
	c.cache().Set(cacheKey, &refreshed)

	path, err := c.diskCachePath(source)
	if err == nil {
		_ = os.Chtimes(path, refreshed.CachedAt, refreshed.CachedAt)
	}

	return &refreshed
}

func (c *Client) loadLocal(ctx context.Context, source, cacheKey string) *Blob {
	cache := c.cache()
	if blob, ok := cache.Get(cacheKey); ok {
		return blob
	}

	blob, ok := c.loadDiskCache(ctx, source)
	if !ok {
		return nil
	}
	cache.Set(cacheKey, blob)

	return blob
}

func (c *Client) shouldRefresh(local *Blob, opts LookupOptions) bool {
	if opts.Refresh {
		if local.CachedAt.IsZero() {
			return true
		}
		return !c.now().Before(local.CachedAt.Add(minRequestDelay))
	}

	if local.CachedAt.IsZero() {
		return true
	}

	return !c.now().Before(local.CachedAt.Add(DefaultRefreshInterval))
}

func (c *Client) fetchAndVerify(ctx context.Context, source string, local *Blob) (*Blob, []byte, bool, error) {
	fetchURL, err := metadataFetchURL(source, local)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return nil, nil, true, nil
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, nil, false, &HTTPStatusError{StatusCode: resp.StatusCode}
	}

	body, err := readLimited(resp.Body, c.maxBlobBytes())
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrFetch, err)
	}

	blob, err := c.parseAndVerify(ctx, body)
	if err != nil {
		return nil, nil, false, err
	}
	return blob, body, false, nil
}

func (c *Client) loadDiskCache(ctx context.Context, source string) (*Blob, bool) {
	path, err := c.diskCachePath(source)
	if err != nil {
		return nil, false
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	blob, err := c.parseAndVerify(ctx, body)
	if err != nil {
		return nil, false
	}

	if info, err := os.Stat(path); err == nil {
		blob.CachedAt = info.ModTime()
	}

	return blob, true
}

func (c *Client) storeDiskCache(source string, body []byte) (time.Time, error) {
	path, err := c.diskCachePath(source)
	if err != nil {
		return time.Time{}, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return time.Time{}, err
	}

	temp, err := os.CreateTemp(dir, ".mds-*.tmp")
	if err != nil {
		return time.Time{}, err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()

	if err := os.Chmod(tempPath, 0o600); err != nil {
		_ = temp.Close()
		return time.Time{}, err
	}

	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		return time.Time{}, err
	}

	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return time.Time{}, err
	}

	if err := temp.Close(); err != nil {
		return time.Time{}, err
	}

	if err := os.Rename(tempPath, path); err != nil {
		return time.Time{}, err
	}
	removeTemp = false
	syncDirBestEffort(dir)

	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, err
	}

	return info.ModTime(), nil
}

func (c *Client) diskCachePath(source string) (string, error) {
	dir := c.cacheDir()
	if dir == "" {
		return "", errors.New("MDS cache dir is empty")
	}

	sum := sha256.Sum256([]byte(source))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".jwt"), nil
}

func (c *Client) parseAndVerify(ctx context.Context, raw []byte) (*Blob, error) {
	verified, err := c.verifier().Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerify, err)
	}

	return blobFromVerified(verified), nil
}

func blobFromVerified(verified *mdsverify.Blob) *Blob {
	entries := make(map[uuid.UUID]*appmds.PayloadEntry, len(verified.Entries))
	for index := range verified.Entries {
		entry := &verified.Entries[index]
		if entry.AAGUID != uuid.Nil {
			entries[entry.AAGUID] = entry
		}
	}

	return &Blob{
		Number:   verified.Number,
		IssuedAt: verified.IssuedAt,
		Entries:  entries,
	}
}

func (c *Client) verifier() *mdsverify.Verifier {
	return &mdsverify.Verifier{
		Source:       c.source(),
		HTTPClient:   c.httpClient(),
		TrustAnchors: c.TrustAnchors,
		Now:          c.Now,
	}
}

func metadataFetchURL(source string, local *Blob) (string, error) {
	if local == nil {
		return source, nil
	}

	u, err := url.Parse(source)
	if err != nil {
		return "", err
	}

	values := u.Query()
	values.Set("localCopySerial", strconv.FormatUint(local.Number, 10))
	u.RawQuery = values.Encode()

	return u.String(), nil
}

func (c *Client) cacheKey(source string) string {
	cacheDir := c.cacheDir()
	if len(c.TrustAnchors) == 0 {
		return source + "\x00anchors=default\x00cache-dir=" + cacheDir
	}

	fingerprints := make([]string, 0, len(c.TrustAnchors))
	for _, anchor := range c.TrustAnchors {
		if anchor == nil {
			continue
		}
		sum := sha256.Sum256(anchor.Raw)
		fingerprints = append(fingerprints, hex.EncodeToString(sum[:]))
	}
	sort.Strings(fingerprints)

	return source + "\x00anchors=" + strings.Join(fingerprints, ",") + "\x00cache-dir=" + cacheDir
}

func (c *Client) source() string {
	if strings.TrimSpace(c.Source) == "" {
		return DefaultSource
	}

	return c.Source
}

func (c *Client) httpClient() *http.Client {
	base := http.DefaultClient
	if c.HTTPClient != nil {
		base = c.HTTPClient
	}

	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &client
}

func (c *Client) cache() Cache {
	if c.Cache != nil {
		return c.Cache
	}

	return defaultCache
}

func (c *Client) cacheDir() string {
	if strings.TrimSpace(c.CacheDir) != "" {
		return c.CacheDir
	}

	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}

	return filepath.Join(dir, cacheNamespace, cacheDirName)
}

func (c *Client) maxBlobBytes() int64 {
	if c.MaxBlobBytes > 0 {
		return c.MaxBlobBytes
	}

	return DefaultMaxBlobBytes
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}

	return time.Now()
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}

	if n > limit {
		return nil, fmt.Errorf("object exceeds %d bytes", limit)
	}

	return buf.Bytes(), nil
}

func syncDirBestEffort(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

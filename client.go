package mds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/telesma-app/mds/internal/mdsverify"
	appmds "github.com/telesma-app/mds/model"
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
	// Refresh requests a network refresh, subject to the minimum request delay.
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

	// CheckedAt is the last successful network retrieval or revalidation.
	CheckedAt time.Time

	attemptedAt time.Time
	refreshErr  error
}

// Lookup returns verified metadata, using cached data with RefreshErr on failure.
// Canceled refreshes and failures without a verified cache return an error.
func (c *Client) Lookup(ctx context.Context, aaguid uuid.UUID, opts LookupOptions) (appmds.LookupResult, error) {
	if aaguid == uuid.Nil() {
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
		CheckedAt:  blob.CheckedAt,
		RefreshErr: blob.refreshErr,
	}

	if found {
		result.Entry = entry
	}

	return result, nil
}

func (c *Client) blob(ctx context.Context, source string, opts LookupOptions) (*Blob, bool, error) {
	cacheKey := c.cacheKey(source)
	local, _ := c.loadLocal(ctx, source, cacheKey)
	if local != nil && !c.shouldRefresh(local, opts) {
		return local, true, nil
	}

	return c.cache().Refresh(ctx, cacheKey, func() (*Blob, bool, error) {
		current, serial := c.loadLocal(ctx, source, cacheKey)
		if current != nil && !c.shouldRefresh(current, opts) {
			return current, true, nil
		}

		return c.refreshBlob(ctx, source, cacheKey, current, serial)
	})
}

func (c *Client) refreshBlob(ctx context.Context, source, cacheKey string, local *Blob, serial uint64) (*Blob, bool, error) {
	attemptedAt := c.now()
	remote, raw, notModified, err := c.fetchAndVerify(ctx, source, serial)
	if err == nil && notModified && local == nil {
		err = fmt.Errorf("%w: server returned 304 without a verified local blob", ErrVerify)
	}
	if err == nil && !notModified && local != nil && remote.Number < local.Number {
		err = fmt.Errorf("%w: BLOB number %d is older than cached number %d", ErrVerify, remote.Number, local.Number)
	}
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, false, contextErr
		}
		if local == nil {
			return nil, false, err
		}
		retained := *local
		retained.attemptedAt = attemptedAt
		retained.refreshErr = err
		c.cache().Set(cacheKey, &retained)
		return &retained, true, nil
	}

	if notModified || local != nil && remote.Number == local.Number {
		return c.markLocalChecked(source, cacheKey, local, attemptedAt), true, nil
	}

	remote.CheckedAt = c.now()
	remote.attemptedAt = attemptedAt
	_ = c.storeDiskCache(source, raw, remote.CheckedAt)
	c.cache().Set(cacheKey, remote)
	return remote, false, nil
}

func (c *Client) markLocalChecked(source, cacheKey string, local *Blob, attemptedAt time.Time) *Blob {
	refreshed := *local
	refreshed.CheckedAt = c.now()
	refreshed.attemptedAt = attemptedAt
	refreshed.refreshErr = nil
	c.cache().Set(cacheKey, &refreshed)

	path, err := c.diskCachePath(source)
	if err == nil {
		_ = os.Chtimes(path, refreshed.CheckedAt, refreshed.CheckedAt)
	}

	return &refreshed
}

func (c *Client) loadLocal(ctx context.Context, source, cacheKey string) (*Blob, uint64) {
	cache := c.cache()
	if blob, ok := cache.Get(cacheKey); ok {
		return blob, blob.Number
	}

	blob, serial := c.loadDiskCache(ctx, source)
	if blob == nil {
		return nil, serial
	}
	cache.Set(cacheKey, blob)

	return blob, blob.Number
}

func (c *Client) shouldRefresh(local *Blob, opts LookupOptions) bool {
	lastRequest := local.CheckedAt
	if local.attemptedAt.After(lastRequest) {
		lastRequest = local.attemptedAt
	}
	interval := DefaultRefreshInterval
	if opts.Refresh {
		interval = minRequestDelay
	}

	return lastRequest.IsZero() || !c.now().Before(lastRequest.Add(interval))
}

func (c *Client) fetchAndVerify(ctx context.Context, source string, serial uint64) (*Blob, []byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	if serial != 0 {
		req.Header.Set("If-None-Match", strconv.FormatUint(serial, 10))
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

func (c *Client) loadDiskCache(ctx context.Context, source string) (*Blob, uint64) {
	path, err := c.diskCachePath(source)
	if err != nil {
		return nil, 0
	}

	body, err := os.ReadFile(path)
	if err != nil {
		return nil, 0
	}

	blob, err := c.parseAndVerify(ctx, body)
	if err != nil {
		return nil, unverifiedBlobSerial(body)
	}

	if info, err := os.Stat(path); err == nil {
		blob.CheckedAt = info.ModTime()
	}

	return blob, blob.Number
}

func (c *Client) storeDiskCache(source string, body []byte, checkedAt time.Time) error {
	path, err := c.diskCachePath(source)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	temp, err := os.CreateTemp(dir, ".mds-*.tmp")
	if err != nil {
		return err
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
		return err
	}

	if _, err := temp.Write(body); err != nil {
		_ = temp.Close()
		return err
	}

	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}

	if err := temp.Close(); err != nil {
		return err
	}

	if err := os.Chtimes(tempPath, checkedAt, checkedAt); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	removeTemp = false
	syncDirBestEffort(dir)

	return nil
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
		if entry.AAGUID != uuid.Nil() {
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

func unverifiedBlobSerial(raw []byte) uint64 {
	parts := bytes.SplitN(raw, []byte("."), 3)
	if len(parts) != 3 {
		return 0
	}

	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return 0
	}

	var claims struct {
		Number uint64 `json:"no"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}

	return claims.Number
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

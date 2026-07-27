package mds

import (
	"context"
	"sync"
)

// Cache stores verified MDS blobs and coordinates refreshes by cache key.
type Cache interface {
	Get(source string) (*Blob, bool)
	Set(source string, blob *Blob)
	Refresh(context.Context, string, func() (*Blob, bool, error)) (*Blob, bool, error)
}

type simpleCache struct {
	mu      sync.RWMutex
	blobs   map[string]*Blob
	refresh map[string]*refreshCall
}

type refreshCall struct {
	done    chan struct{}
	waiters int
	blob    *Blob
	cached  bool
	err     error
}

// NewCache creates a process-local MDS blob cache.
func NewCache() Cache {
	return &simpleCache{
		blobs:   make(map[string]*Blob),
		refresh: make(map[string]*refreshCall),
	}
}

func (c *simpleCache) Get(source string) (*Blob, bool) {
	c.mu.RLock()
	blob, ok := c.blobs[source]
	c.mu.RUnlock()

	return blob, ok
}

func (c *simpleCache) Set(source string, blob *Blob) {
	if blob == nil {
		return
	}

	c.mu.Lock()
	c.blobs[source] = blob
	c.mu.Unlock()
}

func (c *simpleCache) Refresh(
	ctx context.Context,
	key string,
	refresh func() (*Blob, bool, error),
) (*Blob, bool, error) {
	c.mu.Lock()
	if call := c.refresh[key]; call != nil {
		call.waiters++
		c.mu.Unlock()

		select {
		case <-call.done:
			return call.blob, call.cached, call.err
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	call := &refreshCall{done: make(chan struct{}), waiters: 1}
	c.refresh[key] = call
	c.mu.Unlock()

	call.blob, call.cached, call.err = refresh()

	c.mu.Lock()
	delete(c.refresh, key)
	close(call.done)
	c.mu.Unlock()

	return call.blob, call.cached, call.err
}

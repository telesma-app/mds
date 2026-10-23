package mds

// Option configures a Client created by NewClient.
type Option func(*Client)

// NewClient creates an MDS client with cache-first defaults.
// Each option must be non-nil.
func NewClient(options ...Option) *Client {
	client := &Client{}
	for _, option := range options {
		option(client)
	}

	return client
}

// WithCacheDir stores verified MDS JWTs below dir.
func WithCacheDir(dir string) Option {
	return func(client *Client) {
		client.CacheDir = dir
	}
}

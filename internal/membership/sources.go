package membership

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/ohstr/nmilat/nip01"
)

// Source feeds raw events into a Store until ctx ends.
type Source interface {
	Freshness
	Name() string
	Run(ctx context.Context, store *Store) error
}

// syncClock records when a source last completed a full read.
type syncClock struct {
	mu   sync.Mutex
	last time.Time
	err  error
}

func (c *syncClock) LastSync() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// LastError returns the most recent read error, nil after a success.
func (c *syncClock) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *syncClock) done(at time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.last = at
	}
	c.err = err
}

// MaxFeedSize bounds a file or HTTP feed.
const MaxFeedSize = 64 << 20

// maxLine bounds one JSONL line (one event).
const maxLine = 1 << 20

// FileSource reads a JSONL file of signed events, re-reading it on change
// (when watching) and every poll interval.
type FileSource struct {
	syncClock
	Path         string
	Watch        bool
	PollInterval time.Duration
	Log          *slog.Logger
	Now          func() time.Time
}

func (f *FileSource) Name() string { return "file:" + f.Path }

func (f *FileSource) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// ReadOnce reads the whole file into store.
func (f *FileSource) ReadOnce(store *Store) error {
	events, err := readJSONL(f.Path)
	if err == nil {
		store.Ingest(events...)
	}
	f.done(f.now(), err)
	return err
}

func readJSONL(path string) ([]*nip01.Event, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxFeedSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, MaxFeedSize)
	}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	var out []*nip01.Event
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		var ev nip01.Event
		if err := json.Unmarshal(b, &ev); err != nil {
			return nil, fmt.Errorf("%s:%d: not an event", path, line)
		}
		out = append(out, &ev)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

func (f *FileSource) Run(ctx context.Context, store *Store) error {
	logf := func(err error) {
		if err != nil && f.Log != nil {
			f.Log.Warn("membership file unreadable", "path", f.Path, "err", err)
		}
	}
	logf(f.ReadOnce(store))

	var events chan fsnotify.Event
	if f.Watch {
		w, err := fsnotify.NewWatcher()
		if err == nil {
			defer w.Close()
			// Watch the directory so atomic renames (ConfigMap updates,
			// editors) are seen too.
			if err := w.Add(filepath.Dir(f.Path)); err == nil {
				events = w.Events
			}
		}
	}
	t := time.NewTicker(f.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			logf(f.ReadOnce(store))
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if filepath.Clean(ev.Name) == filepath.Clean(f.Path) || filepath.Base(ev.Name) == "..data" {
				logf(f.ReadOnce(store))
			}
		}
	}
}

// HTTPSource polls a URL returning a JSON array of signed events.
type HTTPSource struct {
	syncClock
	URL      string
	Interval time.Duration
	Timeout  time.Duration
	// Headers returns the request headers; called per request so rotated
	// secrets apply.
	Headers func() (http.Header, error)
	Client  *http.Client
	Log     *slog.Logger
	Now     func() time.Time
}

func (h *HTTPSource) Name() string { return "http:" + h.URL }

func (h *HTTPSource) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// NewHTTPClient returns a client trusting caFile in addition to the system
// roots when caFile is set. Redirects are not followed, so headers carrying
// credentials never go to another host.
func NewHTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// FetchOnce fetches the feed into store.
func (h *HTTPSource) FetchOnce(ctx context.Context, store *Store) error {
	events, err := h.fetch(ctx)
	if err == nil {
		store.Ingest(events...)
	}
	h.done(h.now(), err)
	return err
}

func (h *HTTPSource) fetch(ctx context.Context) ([]*nip01.Event, error) {
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		return nil, err
	}
	if h.Headers != nil {
		hdr, err := h.Headers()
		if err != nil {
			return nil, err
		}
		for k, vs := range hdr {
			req.Header[k] = vs
		}
	}
	req.Header.Set("Accept", "application/json")
	client := h.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", h.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxFeedSize {
		return nil, errors.New("feed larger than the size limit")
	}
	var events []*nip01.Event
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("%s: not a JSON array of events", h.URL)
	}
	return events, nil
}

func (h *HTTPSource) Run(ctx context.Context, store *Store) error {
	t := time.NewTicker(h.Interval)
	defer t.Stop()
	for {
		if err := h.FetchOnce(ctx, store); err != nil && h.Log != nil && ctx.Err() == nil {
			h.Log.Warn("membership feed unreachable", "url", h.URL, "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

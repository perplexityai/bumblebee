package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/perplexityai/bumblebee/internal/output"
)

// sinkHTTPOpts groups the HTTP-specific options for --output=http so the
// openSink signature does not balloon. Fields here mirror the
// corresponding --http-* flags one-to-one.
type sinkHTTPOpts struct {
	URL       string
	AuthMode  string
	TokenEnv  string
	KeyEnv    string
	Timeout   time.Duration
	BatchSize int
	AllowHTTP bool
	Gzip      bool
	UserAgent string
}

// openSink returns the io.Writer the emitter should write records to,
// along with a close function to invoke at end-of-scan. dest selects the
// kind ("stdout", "terminal", "file", or "http"); filePath and appendMode
// only apply when dest=="file"; h carries the HTTP-sink options when
// dest=="http".
//
// The returned close function is always non-nil. For stdout it is a
// no-op; for file and http sinks it flushes and releases resources.
func openSink(dest, filePath string, appendMode bool, h sinkHTTPOpts) (io.Writer, func() error, error) {
	switch dest {
	case "", "stdout":
		return os.Stdout, func() error { return nil }, nil
	case "terminal":
		sink := output.NewTerminalSink(os.Stdout)
		return sink, sink.Close, nil
	case "file":
		if filePath == "" {
			return nil, nil, fmt.Errorf("--output=file requires --output-file")
		}
		flag := os.O_WRONLY | os.O_CREATE
		if appendMode {
			flag |= os.O_APPEND
		} else {
			flag |= os.O_TRUNC
		}
		f, err := os.OpenFile(filePath, flag, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("open output file: %w", err)
		}
		return f, f.Close, nil
	case "http":
		auth, err := buildHTTPAuth(h.AuthMode, h.TokenEnv, h.KeyEnv)
		if err != nil {
			return nil, nil, err
		}
		sink, err := output.NewHTTPSink(output.HTTPConfig{
			URL:           h.URL,
			Auth:          auth,
			Timeout:       h.Timeout,
			BatchSize:     h.BatchSize,
			UserAgent:     h.UserAgent,
			AllowInsecure: h.AllowHTTP,
			Gzip:          h.Gzip,
		})
		if err != nil {
			return nil, nil, err
		}
		return sink, sink.Close, nil
	default:
		return nil, nil, fmt.Errorf("unknown --output %q (want stdout|file|http|terminal)", dest)
	}
}

// buildHTTPAuth resolves the --http-auth mode plus its env-var-backed
// credential into an output.HTTPAuth ready for the HTTP sink.
//
// Tokens and HMAC keys are read from environment variables rather than
// CLI literals so credentials do not appear in `ps` or in any plist /
// systemd unit-file commit history.
func buildHTTPAuth(mode, tokenEnv, keyEnv string) (output.HTTPAuth, error) {
	switch mode {
	case "", "none":
		return output.HTTPAuth{Mode: "none"}, nil
	case "bearer":
		if tokenEnv == "" {
			return output.HTTPAuth{}, fmt.Errorf("--http-auth=bearer requires --http-token-env")
		}
		tok := os.Getenv(tokenEnv)
		if tok == "" {
			return output.HTTPAuth{}, fmt.Errorf("env var %q is empty", tokenEnv)
		}
		return output.HTTPAuth{Mode: "bearer", Token: tok}, nil
	case "hmac-sha256":
		if keyEnv == "" {
			return output.HTTPAuth{}, fmt.Errorf("--http-auth=hmac-sha256 requires --http-hmac-key-env")
		}
		key := os.Getenv(keyEnv)
		if key == "" {
			return output.HTTPAuth{}, fmt.Errorf("env var %q is empty", keyEnv)
		}
		return output.HTTPAuth{
			Mode:            "hmac-sha256",
			HMACKey:         []byte(key),
			TimestampHeader: "X-Inventory-Timestamp",
		}, nil
	default:
		return output.HTTPAuth{}, fmt.Errorf("unknown --http-auth %q", mode)
	}
}

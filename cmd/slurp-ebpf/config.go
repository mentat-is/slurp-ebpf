package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Config holds agent configuration parsed from JSON.
type Config struct {
	Gulp GulpConfig `json:"gulp"`
	// max_chunk_size: maximum number of events sent in a single websocket packet
	MaxChunkSize int      `json:"max_chunk_size"`
	Hooks        []string `json:"hooks"`
	BpfObject    string   `json:"bpf_object,omitempty"`
	// process_exclude: list of patterns to exclude events by process.executable (wildcards supported)
	ProcessExclude []string `json:"process_exclude,omitempty"`
}

// GulpConfig contains credentials and URI for Gulp.
type GulpConfig struct {
	URI         string `json:"uri"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	OperationID string `json:"operation_id"`
	// paths for client certificate, private key, and CA certificate (pem)
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	CACertFile string `json:"ca_cert_file,omitempty"`
	// when true, skip TLS server verification (useful for self-signed certs)
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`
}

// loadConfig reads the JSON file at path and returns a Config with defaults.
func loadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.MaxChunkSize <= 0 {
		cfg.MaxChunkSize = 1000
	}
	if cfg.Gulp.URI == "" {
		return nil, fmt.Errorf("gulp.uri is required in config")
	}
	// defaults for certificate files live in ./certs directory
	if cfg.Gulp.CertFile == "" {
		cfg.Gulp.CertFile = "./certs/client.crt"
	}
	if cfg.Gulp.KeyFile == "" {
		cfg.Gulp.KeyFile = "./certs/client.key"
	}
	if cfg.Gulp.CACertFile == "" {
		cfg.Gulp.CACertFile = "./certs/ca.crt"
	}
	return &cfg, nil
}

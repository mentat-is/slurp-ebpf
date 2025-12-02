package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Config holds agent configuration parsed from JSON.
type Config struct {
	Gulp      GulpConfig `json:"gulp"`
	ChunkSize int        `json:"chunk_size"`
	Hooks     []string   `json:"hooks"`
	BpfObject string     `json:"bpf_object,omitempty"`
}

// GulpConfig contains credentials and URI for Gulp.
type GulpConfig struct {
	URI      string `json:"uri"`
	Username string `json:"username"`
	Password string `json:"password"`
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
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = 1000
	}
	if cfg.Gulp.URI == "" {
		return nil, fmt.Errorf("gulp.uri is required in config")
	}
	return &cfg, nil
}

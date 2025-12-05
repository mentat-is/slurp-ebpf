package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Config holds agent configuration parsed from JSON.
type Config struct {
	Gulp GulpConfig `json:"gulp"`
	// max_chunk_size: maximum number of events sent in a single websocket packet
	MaxChunkSize int      `json:"max_chunk_size"`
	Hooks        []string `json:"hooks"`
	// process_exclude: list of patterns to exclude events by process.executable (wildcards supported)
	ProcessExclude []string `json:"process_exclude,omitempty"`
}

// GulpConfig contains credentials and URI for Gulp.
type GulpConfig struct {
	URI         string `json:"uri"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	OperationID string `json:"operation_id"`
	// when true, skip TLS server verification (useful for self-signed certs)
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`
	// when true, use client certificates for mutual TLS when the URI is https
	UseCerts bool `json:"use_certs,omitempty"`
}

// createDefaultConfig writes a default configuration to path.
func createDefaultConfig(path string) error {
	defaultCfg := Config{
		Gulp: GulpConfig{
			URI:         "http://localhost:8080",
			Username:    "admin",
			Password:    "admin",
			OperationID: "test_operation",
		},
		MaxChunkSize: 1000,
		Hooks:        []string{"proc_exec", "conn_outbound", "conn_inbound"},
	}
	b, err := json.MarshalIndent(defaultCfg, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(path, b, 0600)
	if err != nil {
		return err
	}

	// ensure correct ownership when running with sudo
	chownFileOrDirectoryToRealUser(path)
	return err
}

// loadConfig reads the JSON file at path and returns a Config with defaults.
// if the file does not exist, it creates a default config file at that path.
func loadConfig() (*Config, string, error) {
	path := filepath.Join(slurpConfigDir(), "slurp_cfg.json")
	f, err := os.Open(path)
	if err != nil {
		// if the config file does not exist, create a default one
		if os.IsNotExist(err) {
			if err := createDefaultConfig(path); err != nil {
				return nil, "", fmt.Errorf("failed to create default config at %s: %w", path, err)
			}
			fmt.Printf("WARNING: created default config at %s; please edit it and run slurp-ebpf again\n", path)
			os.Exit(0)
		}
		return nil, "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, "", err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, "", err
	}
	if cfg.MaxChunkSize <= 0 {
		cfg.MaxChunkSize = 1000
	}
	if cfg.Gulp.URI == "" {
		return nil, "", fmt.Errorf("gulp.uri is required in config")
	}

	// default hooks when none specified
	// these are logical names that will be expanded below
	if len(cfg.Hooks) == 0 {
		cfg.Hooks = []string{"proc_exec", "conn_outbound", "conn_inbound"}
	}

	// mapping from logical hook names to actual tracepoint sections
	hookMap := map[string][]string{
		"proc_exec": {
			"tracepoint/syscalls/sys_enter_execve",
			"tracepoint/syscalls/sys_exit_execve",
			"tracepoint/sched/sched_process_exec",
		},
		"conn_outbound": {
			"tracepoint/syscalls/sys_enter_connect",
		},
		"conn_inbound": {
			"tracepoint/syscalls/sys_enter_accept",
			"tracepoint/syscalls/sys_exit_accept",
		},
	}

	// expand and deduplicate hooks: if a configured value is a logical
	// name present in hookMap, replace it with the mapped sections.  If
	// it's an explicit tracepoint/kprobe name, keep it as-is.
	expanded := make([]string, 0, len(cfg.Hooks))
	seen := make(map[string]struct{})
	for _, h := range cfg.Hooks {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if mapped, ok := hookMap[h]; ok {
			for _, mh := range mapped {
				if _, exists := seen[mh]; !exists {
					seen[mh] = struct{}{}
					expanded = append(expanded, mh)
				}
			}
		} else {
			if _, exists := seen[h]; !exists {
				seen[h] = struct{}{}
				expanded = append(expanded, h)
			}
		}
	}
	cfg.Hooks = expanded
	dbg("cfg=%+v", cfg)
	return &cfg, path, nil
}

// mkGulpDir creates the gulp configuration directory structure under d and
// returns the directory path. It creates a 'certs' subdirectory for TLS
// certificates.
func mkGulpDir(d string) string {
	certsDir := filepath.Join(d, "certs")
	_ = os.MkdirAll(certsDir, 0700)
	chownFileOrDirectoryToRealUser(d)
	chownFileOrDirectoryToRealUser(certsDir)
	return d
}

// chownFileOrDirectoryToRealUser changes the ownership of path to the real
// user when running with sudo.
func chownFileOrDirectoryToRealUser(path string) {
	if sudoUid := os.Getenv("SUDO_UID"); sudoUid != "" {
		// running with sudo; chown to the original user
		u, err := user.LookupId(sudoUid)
		if err == nil && u != nil {
			uid := os.Getuid()
			gid := os.Getgid()
			fmt.Sscanf(u.Uid, "%d", &uid)
			fmt.Sscanf(u.Gid, "%d", &gid)
			_ = os.Chown(path, uid, gid)
		}
	}
}

// slurpConfigDir returns the directory to read configuration from. It honors
// the SLURP_CONFIG_PATH environment variable and falls back to
// ~/.config/slurp. the directory is created if it does not exist.
func slurpConfigDir() string {
	if p := os.Getenv("SLURP_CONFIG_PATH"); p != "" {
		// use env path
		return mkGulpDir(p)
	}
	// decide base home directory
	// when run via sudo: use the real user's home (check SUDO_UID)
	// when run as real root: use root's home
	var home string
	if sudoUid := os.Getenv("SUDO_UID"); sudoUid != "" {
		// running with sudo; use the original user's home
		u, err := user.LookupId(sudoUid)
		if err == nil && u != nil && u.HomeDir != "" {
			home = u.HomeDir
		} else {
			// fallback to current user's home if lookup fails
			home, _ = os.UserHomeDir()
		}
	} else {
		// normal user or real root; use current user's home
		home, _ = os.UserHomeDir()
	}

	dir := filepath.Join(home, ".config", "slurp")
	return mkGulpDir(dir)
}

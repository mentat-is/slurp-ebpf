package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

// JSendResponse models the login response from Gulp.
type JSendResponse struct {
	Status        string          `json:"status"`
	TimestampMsec int64           `json:"timestamp_msec"`
	ReqID         string          `json:"req_id"`
	Data          json.RawMessage `json:"data"`
}

// GulpWsAuthPacket is used to authenticate the ingest websocket.
type GulpWsAuthPacket struct {
	Token        string   `json:"token"`
	WsID         *string  `json:"ws_id,omitempty"`
	OperationIDs []string `json:"operation_ids,omitempty"`
	Types        []string `json:"types,omitempty"`
	Data         any      `json:"data,omitempty"`
	ReqID        *string  `json:"req_id,omitempty"`
}

// GulpWsIngestPacket represents the metadata packet sent before a binary chunk.
type GulpWsIngestPacket struct {
	Index        string `json:"index"`
	OperationID  string `json:"operation_id"`
	WsID         string `json:"ws_id"`
	ReqID        string `json:"req_id"`
	Flt          any    `json:"flt,omitempty"`
	Plugin       string `json:"plugin"`
	PluginParams any    `json:"plugin_params,omitempty"`
	Last         bool   `json:"last"`
}

// GulpWsData represents the generic websocket message envelope from Gulp/UI.
type GulpWsData struct {
	Timestamp   int64           `json:"@timestamp"`
	Type        string          `json:"type"`
	Private     bool            `json:"private,omitempty"`
	Internal    bool            `json:"internal,omitempty"`
	Payload     json.RawMessage `json:"payload,omitempty"`
	WsID        *string         `json:"ws_id,omitempty"`
	UserID      *string         `json:"user_id,omitempty"`
	ReqID       *string         `json:"req_id,omitempty"`
	OperationID *string         `json:"gulp.operation_id,omitempty"`
}

// GulpWsAcknowledgedPacket is sent by Gulp when a websocket connection is accepted.
type GulpWsAcknowledgedPacket struct {
	WsID  string `json:"ws_id"`
	ReqID string `json:"req_id"`
	Token string `json:"token"`
}

// waitConnectionAck runs a continuous reader loop and reports any final error.
func waitConnectionAck(conn *websocket.Conn, ackCh chan<- GulpWsAcknowledgedPacket, errCh chan<- error) {
	acked := false
	for {
		_, m, err := conn.ReadMessage()
		if err != nil {
			// report final error and exit
			select {
			case errCh <- err:
			default:
			}
			return
		}
		var d GulpWsData
		if err := json.Unmarshal(m, &d); err != nil {
			continue
		}
		dbg("received ws message type=%s payload_len=%d", d.Type, len(d.Payload))
		if d.Type == "ws_connected" && !acked {
			var a GulpWsAcknowledgedPacket
			if err := json.Unmarshal(d.Payload, &a); err == nil {
				// deliver the handshake ack and continue reading for control messages
				ackCh <- a
				acked = true
			}
		}
		// ignore other messages, keep reading so pongs/control frames are processed
	}
}

// login authenticates to the Gulp HTTP API using the login endpoint and returns a token.
func login(ctx context.Context, g GulpConfig) (string, error) {
	loginURL := strings.TrimRight(g.URI, "/") + "/login"
	body := map[string]string{"user_id": g.Username, "password": g.Password}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", loginURL, strings.NewReader(string(b)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client, err := httpClientForGulp(g)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data := make([]byte, 0)
	if resp.Body != nil {
		data, _ = io.ReadAll(resp.Body)
	}
	var jr JSendResponse
	if err := json.Unmarshal(data, &jr); err != nil {
		return "", fmt.Errorf("failed to parse login response: %w", err)
	}
	if jr.Status != "success" {
		return "", fmt.Errorf("login failed: %s", string(data))
	}
	// try to extract token
	var s string
	if err := json.Unmarshal(jr.Data, &s); err == nil && s != "" {
		return s, nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(jr.Data, &obj); err == nil {
		if t, ok := obj["token"].(string); ok && t != "" {
			return t, nil
		}
	}
	return "", fmt.Errorf("no token found in login response.data")
}

// tlsConfigFromGulp builds a tls.Config based on paths in GulpConfig. If no
// cert/key/ca are present the returned tls.Config may be nil.
func tlsConfigFromGulp(g GulpConfig) (*tls.Config, error) {
	// if TLS is not requested at all, return nil to indicate no TLS config
	if !shouldUseTLS(g) {
		return nil, nil
	}

	var cfg tls.Config

	// try to load client cert if both provided and exist
	if g.CertFile != "" && g.KeyFile != "" {
		if _, err := os.Stat(g.CertFile); err == nil {
			if _, err := os.Stat(g.KeyFile); err == nil {
				cert, err := tls.LoadX509KeyPair(g.CertFile, g.KeyFile)
				if err != nil {
					return nil, fmt.Errorf("failed to load client cert/key: %w", err)
				}
				cfg.Certificates = []tls.Certificate{cert}
			}
		}
	}

	// load custom CA if provided
	if g.CACertFile != "" {
		if b, err := os.ReadFile(g.CACertFile); err == nil {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				return nil, fmt.Errorf("failed to parse CA cert PEM")
			}
			cfg.RootCAs = pool
		}
	}

	if g.SkipTLSVerify {
		cfg.InsecureSkipVerify = true
	}

	return &cfg, nil
}

// httpClientForGulp constructs an http.Client that uses TLS settings provided
// by the gulp section (client certs / ca / self-signed option).
func httpClientForGulp(g GulpConfig) (*http.Client, error) {
	// only configure TLS on the transport if we actually need TLS
	useTLS := shouldUseTLS(g)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if useTLS {
		tlsCfg, err := tlsConfigFromGulp(g)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &http.Client{Transport: tr}, nil
}

// shouldUseTLS returns true when we should enable TLS for connections.
// TLS is enabled when the gulp URI uses https, when client certs/CA are
// provided, or when use_self_signed is set.
func shouldUseTLS(g GulpConfig) bool {
	// if uri explicitly https, use TLS
	if strings.HasPrefix(strings.ToLower(g.URI), "https://") {
		return true
	}
	// if skip-tls-verify option requested, enable TLS (but skip verification)
	if g.SkipTLSVerify {
		return true
	}
	// if any of the cert files are present on disk, enable TLS
	if g.CertFile != "" {
		if _, err := os.Stat(g.CertFile); err == nil {
			return true
		}
	}
	if g.KeyFile != "" {
		if _, err := os.Stat(g.KeyFile); err == nil {
			return true
		}
	}
	if g.CACertFile != "" {
		if _, err := os.Stat(g.CACertFile); err == nil {
			return true
		}
	}
	return false
}

// wsURLFromURI builds the websocket ingest URL from the base URI. If useTLS
// is true the returned scheme will be `wss`, otherwise `ws`.
func wsURLFromURI(uri string, useTLS bool) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	// prefer explicit scheme if provided
	if u.Scheme == "https" || u.Scheme == "http" {
		if u.Scheme == "https" || useTLS {
			u.Scheme = "wss"
		} else {
			u.Scheme = "ws"
		}
	} else {
		if useTLS {
			u.Scheme = "wss"
		} else {
			u.Scheme = "ws"
		}
	}
	u.Path = "/ws_ingest_raw"
	return u.String(), nil
}

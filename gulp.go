package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	resp, err := http.DefaultClient.Do(req)
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

// wsURLFromURI builds the websocket ingest URL from the base URI.
func wsURLFromURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	scheme := "ws"
	if u.Scheme == "https" {
		scheme = "wss"
	}
	u.Scheme = scheme
	u.Path = "/ws_ingest_raw"
	return u.String(), nil
}

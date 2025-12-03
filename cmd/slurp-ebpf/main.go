package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// Event is a generic event shape we will send as raw data
type Event map[string]any

var globalSeq uint64
var debug bool

func dbg(format string, args ...interface{}) {
	if !debug {
		return
	}
	log.Printf(format, args...)
}

// buildContextIDs computes context/source ids from hostname
func buildContextIDs() (string, string) {
	hn, _ := os.Hostname()
	h := sha1.Sum([]byte(hn))
	hexh := hex.EncodeToString(h[:])
	// use full sha1 hex as context_id and source_id
	return hexh, hexh
}

func osHostnameOrEmpty() string {
	hn, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hn
}

// Chunk sender and reader helpers were moved to separate files in the project root.

// Chunk sender and reader helpers were moved to separate files in the project root.

func main() {
	cfgPath := flag.String("config", "slurp_cfg.json", "path to config file")
	dbgFlag := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()
	debug = *dbgFlag
	dbg("starting slurp-ebpf (debug=%v)", debug)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(2)
	}
	dbg("loaded config from %s", *cfgPath)

	// if hooks empty, add defaults
	if len(cfg.Hooks) == 0 {
		cfg.Hooks = []string{"sys_enter_execve", "sys_exit_open", "kprobe__do_sys_open"}
	}
	dbg("hooks: %v", cfg.Hooks)

	// login to Gulp HTTP API to get token
	token, err := login(ctx, cfg.Gulp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(2)
	}
	dbg("login successful, token length=%d", len(token))

	wsURL, err := wsURLFromURI(cfg.Gulp.URI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid gulp uri: %v\n", err)
		os.Exit(2)
	}
	dbg("ws url resolved: %s", wsURL)

	// connect to websocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "websocket dial error: %v\n", err)
		os.Exit(2)
	}
	defer conn.Close()
	dbg("websocket connection established")

	auth := GulpWsAuthPacket{Token: token}
	aj, _ := json.Marshal(auth)
	if err := conn.WriteMessage(websocket.TextMessage, aj); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send auth: %v\n", err)
		os.Exit(2)
	}
	dbg("sent auth packet to websocket")

	// read loop to wait for websocket acknowledgement (GulpWsAcknowledgedPacket in payload)
	ackCh := make(chan GulpWsAcknowledgedPacket, 1)
	readErrCh := make(chan error, 1)
	var wsID, reqID string
	go waitConnectionAck(conn, ackCh, readErrCh)
	var ack GulpWsAcknowledgedPacket
	select {
	case ack = <-ackCh:
		// got acknowledgement
		wsID = ack.WsID
		reqID = ack.ReqID
		dbg("websocket acknowledged: ws_id=%s req_id=%s", wsID, reqID)
	case <-time.After(10 * time.Second):
		fmt.Fprintln(os.Stderr, "timeout waiting for websocket acknowledgement")
		os.Exit(2)
	case <-ctx.Done():
		os.Exit(0)
	}

	// ok, we're connected and acknowledged
	fmt.Println("Press Ctrl-C to stop slurp and flush pending events; slurp will send a final chunk before exiting.")

	// start event producer from eBPF object (reader will also send chunks)
	prodCtx, prodCancel := context.WithCancel(ctx)
	bpfPath := cfg.BpfObject
	if bpfPath == "" {
		bpfPath = "./slurp_bpf.o"
	}
	if _, err := os.Stat(bpfPath); err != nil {
		fmt.Fprintf(os.Stderr, "bpf object not found: %s\n", bpfPath)
		os.Exit(2)
	}
	ebpfErrCh := make(chan error, 1)
	dbg("starting ebpf reader with object: %s", bpfPath)
	go readEbpfEvents(prodCtx, bpfPath, conn, cfg, wsID, reqID, ebpfErrCh)

	select {
	case err := <-ebpfErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: ebpf reader failed to start: %v\n", err)
			os.Exit(2)
		}
	case <-time.After(300 * time.Millisecond):
		// assume ebpf reader is running
	}

	// wait for termination or error
	select {
	case <-ctx.Done():
		prodCancel()
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	case err := <-ebpfErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: ebpf reader failed: %v\n", err)
			os.Exit(2)
		}
	case err := <-readErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			os.Exit(2)
		}
	}

	dbg("exiting slurp-ebpf")
	fmt.Println("exiting slurp-ebpf")
}

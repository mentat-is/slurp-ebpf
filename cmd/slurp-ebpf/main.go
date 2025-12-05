package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/socialviolation/asciiban/ascii"
)

// debugFlag is set via --debugFlag flag
var debugFlag bool

// AppVersion is set during build via ldflags (default is "dev". see build.sh)
var AppVersion = "dev"

func dbg(format string, args ...interface{}) {
	if !debugFlag {
		return
	}
	log.Printf(format, args...)
}

// getAppVersion returns the embedded application version string with git commit hash.
func getAppVersion() string {
	buildInfo, _ := debug.ReadBuildInfo()
	var build string

	for _, setting := range buildInfo.Settings {
		if setting.Key == "vcs.revision" {
			// git commit hash
			build = setting.Value
		} else if setting.Key == "main.AppVersion" {
			// set by ldflags during build (i.e. 1.0.0)
			AppVersion = setting.Value
		}
	}

	// return version string
	return fmt.Sprintf("%s(%s)", AppVersion, build[:8])
}

// banner renders and returns the slurp ASCII art banner.
func banner() string {
	// select a random font and palette
	fonts := ascii.GetFonts()
	var font string = ascii.RandomFont(fonts...)
	var palette ascii.Palette = ascii.RandomPalette()

	// render banner to string
	s := ascii.Render([]ascii.BannerOption{ascii.WithMessage("slurp"), ascii.WithFont(font), ascii.WithPalette(palette)}...)
	s += "\neBPF-powered realtime ingestion agent for https://github.com/mentat-is/gulp"
	s += fmt.Sprintf("\nversion: %s\n", getAppVersion())
	return s
}

func main() {
	cfgDir := slurpConfigDir()
	dbgFlag := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()
	debugFlag = *dbgFlag
	
	fmt.Printf("%s\n\n. starting slurp-ebpf (config dir=%s, debug=%v)\n", banner(), cfgDir, debugFlag)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// load configuration
	cfg, cfgPath, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(2)
	}
	dbg("loaded config from %s", cfgPath)

	// login to Gulp HTTP API to get token
	token, err := login(ctx, cfg.Gulp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(2)
	}
	dbg("login successful, token length=%d", len(token))

	// decide whether to use TLS: only use TLS when the gulp URI is https.
	// otherwise use plain ws/http.
	useTLS := shouldUseTLS(cfg.Gulp)
	var wsURL string
	wsURL, err = wsURLFromURI(cfg.Gulp.URI, useTLS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid gulp uri: %v\n", err)
		os.Exit(2)
	}
	dbg("ws url resolved: %s", wsURL)

	// build tls config only if TLS is requested
	var tlsCfg *tls.Config
	if useTLS {
		tlsCfg, err = tlsConfigFromGulp(cfg.Gulp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to build TLS config: %v\n", err)
			os.Exit(2)
		}
	}

	// connect to websocket
	dialer := websocket.Dialer{TLSClientConfig: tlsCfg}
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "websocket dial error: %v\n", err)
		os.Exit(2)
	}
	dbg("websocket connection established")

	// set a pong handler and read deadline so pongs extend the read deadline
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// create a writer helper with a bounded queue and a periodic ping
	ws := NewWSClient(conn, 1024, 25*time.Second)

	// send auth via the async writer
	auth := GulpWsAuthPacket{Token: token}
	aj, _ := json.Marshal(auth)
	if err := ws.SendRaw(websocket.TextMessage, aj); err != nil {
		fmt.Fprintf(os.Stderr, "failed to queue auth: %v\n", err)
		os.Exit(2)
	}
	dbg("queued auth packet to websocket")

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
	bpfPath := filepath.Join(cfgDir, "slurp_ebpf.o")
	if _, err := os.Stat(bpfPath); err != nil {
		fmt.Fprintf(os.Stderr, "bpf object not found: %s\n", bpfPath)
		os.Exit(2)
	}
	ebpfErrCh := make(chan error, 1)
	dbg("starting ebpf reader with object: %s", bpfPath)
	go readEbpfEvents(prodCtx, bpfPath, ws, cfg, wsID, reqID, ebpfErrCh)

	select {
	case err := <-ebpfErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: ebpf reader failed to start: %v\n", err)
			os.Exit(2)
		}
	case <-time.After(300 * time.Millisecond):
		// assume ebpf reader is running
		dbg("300ms passed")
	}

	// wait for termination or error
	select {
	case <-ctx.Done():
		dbg("ctx Done, canceling...")
		prodCancel()
		_ = ws.Close()
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

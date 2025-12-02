package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Configuration types and loader are defined in separate file when available.

// login and websocket packet types are implemented in gulp.go

// wsURLFromURI lives in gulp.go

// Gulp websocket packet types are defined in gulp.go

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

// ebpfEventReader loads a compiled BPF object and reads events from a perf map named "events".
// Each perf sample is expected to contain JSON; if not, the raw bytes are wrapped.
func ebpfEventReader(ctx context.Context, bpfPath string, out chan<- Event) error {
	defer close(out)
	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		return fmt.Errorf("loading bpf spec: %w", err)
	}
	dbg("loaded bpf spec: %s", bpfPath)
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("creating bpf collection: %w", err)
	}
	dbg("created bpf collection")
	defer coll.Close()

	m, ok := coll.Maps["events"]
	if !ok {
		return fmt.Errorf("bpf object has no map named 'events'")
	}
	dbg("found map 'events' in bpf collection")

	// create ringbuf reader
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("creating ringbuf reader: %w", err)
	}
	dbg("ringbuf reader created")
	defer reader.Close()

	contextID, sourceID := buildContextIDs()
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		rec, err := reader.Read()
		if err != nil {
			// ringbuf.Reader returns io.EOF when closed
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			continue
		}
		// debug: report ringbuf record metadata
		dbg("ringbuf record: sample_len=%d", len(rec.RawSample))
		// parse binary struct produced by slurp_bpf.c
		// layout: uint64 ts_ms;
		//         uint32 pid;
		//         uint32 tgid;
		//         uint32 uid;
		//         uint32 gid;
		//         uint32 evt_type;
		//         char comm[16];
		//         char filename[256]
		raw := rec.RawSample
		var tsMs uint64
		var pid uint32
		var tgid uint32
		var uid uint32
		var gid uint32
		var evtType uint32
		var comm string
		var filename string
		if len(raw) >= 8 {
			tsMs = binary.LittleEndian.Uint64(raw[0:8])
		}
		if len(raw) >= 16 {
			pid = binary.LittleEndian.Uint32(raw[8:12])
			tgid = binary.LittleEndian.Uint32(raw[12:16])
		}
		if len(raw) >= 28 {
			uid = binary.LittleEndian.Uint32(raw[16:20])
			gid = binary.LittleEndian.Uint32(raw[20:24])
			evtType = binary.LittleEndian.Uint32(raw[24:28])
		}
		if len(raw) >= 44 {
			commBytes := raw[28:44]
			// comm is NUL-terminated
			if i := bytes.IndexByte(commBytes, 0); i >= 0 {
				comm = string(commBytes[:i])
			} else {
				comm = string(commBytes)
			}
		}
		if len(raw) >= 44+1 {
			// filename up to 256 bytes
			end := 44 + 256
			if end > len(raw) {
				end = len(raw)
			}
			fnameBytes := raw[44:end]
			if i := bytes.IndexByte(fnameBytes, 0); i >= 0 {
				filename = string(fnameBytes[:i])
			} else {
				filename = string(fnameBytes)
			}
		}

		// assemble GulpDocument-like map
		seq := atomic.AddUint64(&globalSeq, 1)
		id := strings.ReplaceAll(uuid.NewString(), "-", "")
		ts := time.UnixMilli(int64(tsMs)).UTC().Format(time.RFC3339)
		gulpTs := int64(tsMs) * int64(time.Millisecond) / int64(time.Nanosecond) // convert ms to ns
		// note: tsMs is milliseconds; convert: ns = ms * 1e6
		gulpTs = int64(tsMs) * 1_000_000

		// map evtType to action/name
		evtAction := "unknown"
		switch evtType {
		case 1:
			evtAction = "execve"
		case 2:
			evtAction = "openat_enter"
		case 3:
			evtAction = "openat_exit"
		case 4:
			evtAction = "do_sys_open_kprobe"
		}

		e := Event{
			"_id":                    id,
			"@timestamp":             ts,
			"gulp.timestamp":         gulpTs,
			"gulp.timestamp_invalid": false,
			"gulp.operation_id":      "test_operation",
			"gulp.context_id":        contextID,
			"gulp.source_id":         sourceID,
			"agent.type":             "ebpf",
			"event.original":         fmt.Sprintf("comm=%s pid=%d tgid=%d uid=%d gid=%d filename=%s", comm, pid, tgid, uid, gid, filename),
			"event.sequence":         int(seq),
			"event.code":             "0",
			"gulp.event_code":        0,
			"event.duration":         1,
			"process.name":           comm,
			"process.pid":            pid,
			"process.executable":     comm,
			"user.uid":               int(uid),
			"user.gid":               int(gid),
			"event.action":           evtAction,
			"host.hostname":          osHostnameOrEmpty(),
			"file.path":              filename,
			"file.name":              filename,
			"ebpf.filename":          filename,
		}
		dbg("event parsed: pid=%d comm=%s filename=%s evtType=%d seq=%d", pid, comm, filename, evtType, seq)
		select {
		case <-ctx.Done():
			return nil
		case out <- e:
		}
	}
}

func sendChunks(ctx context.Context, conn *websocket.Conn, cfg *Config, wsID string, reqID string, in <-chan Event) error {
	chunk := make([]Event, 0, cfg.ChunkSize)
	sendPacket := func(last bool) error {
		if len(chunk) == 0 && !last {
			return nil
		}
		p := GulpWsIngestPacket{
			Index:       "test_operation",
			OperationID: "test_operation",
			WsID:        wsID,
			ReqID:       reqID,
			Plugin:      "raw",
			Last:        last,
		}
		dbg("sending ingest packet last=%v items=%d", last, len(chunk))
		pj, _ := json.Marshal(p)
		if err := conn.WriteMessage(websocket.TextMessage, pj); err != nil {
			return err
		}
		raw, _ := json.Marshal(chunk)
		if err := conn.WriteMessage(websocket.BinaryMessage, raw); err != nil {
			return err
		}
		dbg("sent ingest packet (text+binary) items=%d", len(chunk))
		chunk = chunk[:0]
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			_ = sendPacket(true)
			return nil
		case e, ok := <-in:
			if !ok {
				dbg("input channel closed; will wait up to 30s for events before exiting sendChunks")
				// wait a short while for possible late events or shutdown
				select {
				case <-ctx.Done():
					_ = sendPacket(true)
					return nil
				case <-time.After(30 * time.Second):
					dbg("no new events received after channel close; flushing and exiting sendChunks")
					_ = sendPacket(true)
					return nil
				}
			}
			chunk = append(chunk, e)
			// debug queued event sequence if present
			if seqv, ok := e["event.sequence"]; ok {
				dbg("queued event seq=%v chunk_len=%d", seqv, len(chunk))
			}
			if len(chunk) >= cfg.ChunkSize {
				if err := sendPacket(false); err != nil {
					return err
				}
			}
		}
	}
}

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

	//reqID := aj.req_id
	//wsID := aj["ws_id"]

	// read loop to wait for websocket acknowledgement (GulpWsAcknowledgedPacket in payload)
	ackCh := make(chan GulpWsAcknowledgedPacket, 1)
	var readErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, m, err := conn.ReadMessage()
			if err != nil {
				readErr = err
				return
			}
			var d GulpWsData
			if err := json.Unmarshal(m, &d); err != nil {
				continue
			}
			dbg("received ws message type=%s payload_len=%d", d.Type, len(d.Payload))
			// check for acknowledged packet in payload; send ack once but continue reading
			if d.Type == "ws_connected" {
				if len(d.Payload) > 0 {
					var a GulpWsAcknowledgedPacket
					if err := json.Unmarshal(d.Payload, &a); err == nil {
						dbg("parsed acknowledged packet: ws_id=%s req_id=%s token_len=%d", a.WsID, a.ReqID, len(a.Token))
						// non-blocking send in case receiver already moved on
						select {
						case ackCh <- a:
						default:
						}
						// continue reading further messages
						continue
					}
				}
				// payloadless acknowledgement may still indicate connection; send empty but keep reading
				select {
				case ackCh <- GulpWsAcknowledgedPacket{WsID: "", ReqID: "", Token: ""}:
				default:
				}
				continue
			}
		}
	}()
	var ack GulpWsAcknowledgedPacket
	select {
	case ack = <-ackCh:
		// got acknowledgement
	case <-time.After(10 * time.Second):
		fmt.Fprintln(os.Stderr, "timeout waiting for websocket acknowledgement")
		os.Exit(2)
	case <-ctx.Done():
		os.Exit(0)
	}

	wsID := ack.WsID
	if wsID == "" {
		wsID = "slurp_ws"
	}
	reqID := ack.ReqID
	if reqID == "" {
		reqID = uuid.NewString()
	}

	// Inform operator how to exit and flush pending events
	fmt.Println("Press Ctrl-C to stop slurp and flush pending events; slurp will send a final chunk before exiting.")

	// start event producer from eBPF object
	evtCh := make(chan Event, 1024)
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
	go func() {
		ebpfErrCh <- ebpfEventReader(prodCtx, bpfPath, evtCh)
	}()

	select {
	case err := <-ebpfErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "ebpf reader start failed: %v\n", err)
			os.Exit(2)
		}
	case <-time.After(300 * time.Millisecond):
		// assume ebpf reader is running
	}

	// send chunks
	sendErrCh := make(chan error, 1)
	dbg("starting sendChunks goroutine")
	go func() {
		sendErrCh <- sendChunks(ctx, conn, cfg, wsID, reqID, evtCh)
	}()

	// Inject one synthetic event when debugging to validate the pipeline
	if debug {
		testEvt := Event{
			"_id":          "test-event-1",
			"@timestamp":   time.Now().UTC().Format(time.RFC3339),
			"event.action": "test_inject",
			"process.name": "slurp-test",
		}
		dbg("injecting synthetic test event into evtCh")
		select {
		case evtCh <- testEvt:
			dbg("synthetic event injected")
		default:
			dbg("evtCh full; synthetic event not injected")
		}
	}

	// wait for termination or error
	select {
	case <-ctx.Done():
		prodCancel()
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	case err := <-sendErrCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "send error: %v\n", err)
			os.Exit(2)
		}
	case err := <-func() chan error {
		ch := make(chan error, 1)
		go func() { wg.Wait(); ch <- readErr }()
		return ch
	}():
		if err != nil {
			fmt.Fprintf(os.Stderr, "read error: %v\n", err)
			os.Exit(2)
		}
	}

	dbg("exiting slurp-ebpf")
	fmt.Println("exiting slurp-ebpf")
}

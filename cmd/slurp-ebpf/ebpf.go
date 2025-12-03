// CLEANED BY COPILOT: single-file ebpf reader implementation
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// ebpfSetup loads the BPF collection, attaches programs declared in cfg.Hooks
// and returns a ringbuf.Reader plus a cleanup function the caller must invoke.
func ebpfSetup(bpfPath string, cfg *Config) (*ringbuf.Reader, func(), error) {
	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading bpf spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, nil, fmt.Errorf("creating bpf collection: %w", err)
	}

	var linksArr []link.Link
	// build allowed hook set from config; if empty, no hooks are attached
	allowed := map[string]struct{}{}
	if cfg != nil {
		for _, h := range cfg.Hooks {
			if h == "" {
				continue
			}
			allowed[h] = struct{}{}
		}
	}
	for progName, ps := range spec.Programs {
		sec := ps.SectionName
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}
		switch {
		case strings.HasPrefix(sec, "tracepoint/"):
			parts := strings.SplitN(sec, "/", 3)
			if len(parts) >= 3 {
				// parts[2] is the tracepoint name (eg: sys_enter_execve)
				// only attach if explicitly allowed in cfg.Hooks. support both
				// short-name (sys_enter_execve) and full-section (tracepoint/syscalls/sys_enter_execve).
				tpName := parts[2]
				full := sec
				if len(allowed) > 0 {
					if _, ok := allowed[tpName]; !ok {
						if _, ok2 := allowed[full]; !ok2 {
							// not requested; skip attaching
							continue
						}
					}
				} else {
					// no hooks declared -> skip attaching
					continue
				}

				lnk, err := link.Tracepoint(parts[1], parts[2], prog, nil)
				if err != nil {
					for _, lk := range linksArr {
						lk.Close()
					}
					coll.Close()
					return nil, nil, fmt.Errorf("attach tracepoint %s/%s: %w", parts[1], parts[2], err)
				}
				linksArr = append(linksArr, lnk)
			}
		case strings.HasPrefix(sec, "kprobe/"):
			kname := sec[len("kprobe/"):]
			// only attach if configured
			if len(allowed) > 0 {
				if _, ok := allowed[kname]; !ok {
					if _, ok2 := allowed[sec]; !ok2 {
						continue
					}
				}
			} else {
				// no hooks declared -> skip attaching
				continue
			}

			lnk, err := link.Kprobe(kname, prog, nil)
			if err != nil {
				for _, lk := range linksArr {
					lk.Close()
				}
				coll.Close()
				return nil, nil, fmt.Errorf("attach kprobe %s: %w", kname, err)
			}
			linksArr = append(linksArr, lnk)
		case strings.HasPrefix(sec, "kretprobe/"):
			kname := sec[len("kretprobe/"):]
			// only attach if configured
			if len(allowed) > 0 {
				if _, ok := allowed[kname]; !ok {
					if _, ok2 := allowed[sec]; !ok2 {
						continue
					}
				}
			} else {
				// no hooks declared -> skip attaching
				continue
			}

			lnk, err := link.Kretprobe(kname, prog, nil)
			if err != nil {
				for _, lk := range linksArr {
					lk.Close()
				}
				coll.Close()
				return nil, nil, fmt.Errorf("attach kretprobe %s: %w", kname, err)
			}
			linksArr = append(linksArr, lnk)
		}
	}

	m, ok := coll.Maps["events"]
	if !ok {
		for _, lk := range linksArr {
			lk.Close()
		}
		coll.Close()
		return nil, nil, fmt.Errorf("bpf object has no map named 'events'")
	}

	reader, err := ringbuf.NewReader(m)
	if err != nil {
		for _, lk := range linksArr {
			lk.Close()
		}
		coll.Close()
		return nil, nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}

	cleanup := func() {
		reader.Close()
		for _, lk := range linksArr {
			lk.Close()
		}
		coll.Close()
	}
	return reader, cleanup, nil
}

// sendPacket writes the ingest metadata then the binary JSON chunk.
func sendPacket(conn *websocket.Conn, cfg *Config, wsID, reqID string, chunk *[]Event, last bool) error {
	if len(*chunk) == 0 && !last {
		return nil
	}
	p := GulpWsIngestPacket{
		Index:       cfg.Gulp.OperationID,
		OperationID: cfg.Gulp.OperationID,
		WsID:        wsID,
		ReqID:       reqID,
		Plugin:      "raw",
		Last:        last,
	}
	pj, _ := json.Marshal(p)
	if err := conn.WriteMessage(websocket.TextMessage, pj); err != nil {
		return err
	}
	raw, _ := json.Marshal(*chunk)
	if err := conn.WriteMessage(websocket.BinaryMessage, raw); err != nil {
		return err
	}
	*chunk = (*chunk)[:0]
	return nil
}

// ebpfEventReader reads events, batches up to cfg.ChunkSize, and sends them inline.
func ebpfEventReader(ctx context.Context, bpfPath string, conn *websocket.Conn, cfg *Config, wsID, reqID string) error {
	reader, cleanup, err := ebpfSetup(bpfPath, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	contextID, sourceID := buildContextIDs()
	chunk := make([]Event, 0, cfg.ChunkSize)

	for {
		select {
		case <-ctx.Done():
			_ = sendPacket(conn, cfg, wsID, reqID, &chunk, true)
			return nil
		default:
		}

		rec, err := reader.Read()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				_ = sendPacket(conn, cfg, wsID, reqID, &chunk, true)
				return nil
			default:
			}
			continue
		}

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
			if i := bytes.IndexByte(commBytes, 0); i >= 0 {
				comm = string(commBytes[:i])
			} else {
				comm = string(commBytes)
			}
		}
		if len(raw) >= 44+1 {
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

		seq := atomic.AddUint64(&globalSeq, 1)
		id := strings.ReplaceAll(uuid.NewString(), "-", "")
		ts := time.UnixMilli(int64(tsMs)).UTC().Format(time.RFC3339)
		gulpTs := int64(tsMs) * 1_000_000

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

		chunk = append(chunk, e)
		if len(chunk) >= cfg.ChunkSize {
			if err := sendPacket(conn, cfg, wsID, reqID, &chunk, false); err != nil {
				return err
			}
		}
	}
}

// readEbpfEvents is a small wrapper used by the caller to start the reader.
func readEbpfEvents(ctx context.Context, bpfPath string, conn *websocket.Conn, cfg *Config, wsID, reqID string, errCh chan<- error) {
	err := ebpfEventReader(ctx, bpfPath, conn, cfg, wsID, reqID)
	select {
	case errCh <- err:
	default:
	}
}

// CLEANED BY COPILOT: single-file ebpf reader implementation
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
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
func sendPacket(ws *WSClient, cfg *Config, wsID, reqID string, chunk *[]Event, last bool) error {
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
	// queue text metadata; if queue full drop and continue
	if err := ws.SendRaw(websocket.TextMessage, pj); err != nil {
		dbg("sendPacket: queued text packet failed: %v", err)
		// if client closed, return error to stop reader
		return err
	}
	raw, _ := json.Marshal(*chunk)
	if err := ws.SendRaw(websocket.BinaryMessage, raw); err != nil {
		dbg("sendPacket: queued binary packet failed: %v", err)
		return err
	}
	*chunk = (*chunk)[:0]
	return nil
}

// ebpfEventReader reads events, batches up to cfg.MaxChunkSize, and sends them inline.
func ebpfEventReader(ctx context.Context, bpfPath string, ws *WSClient, cfg *Config, wsID, reqID string) error {
	reader, cleanup, err := ebpfSetup(bpfPath, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	contextID, sourceID := buildContextIDs()
	// use configured max chunk size as capacity for buffered events
	chunk := make([]Event, 0, cfg.MaxChunkSize)

	// ticker to flush events every 15 seconds
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// spawn a reader goroutine to convert the blocking Read() into channel events
	recCh := make(chan ringbuf.Record)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			rec, err := reader.Read()
			if err != nil {
				// non-blocking send of error; allow main loop to handle sleep/retry
				select {
				case readErrCh <- err:
				default:
				}
				continue
			}
			recCh <- rec
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = sendPacket(ws, cfg, wsID, reqID, &chunk, true)
			return nil
		case rec := <-recCh:
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
		// convert bpf monotonic ms to wall-clock time
		evtNs := int64(tsMs) * 1_000_000
		wallT, wallNs := monotonicNsToWallTime(evtNs)
		ts := wallT.Format(time.RFC3339)
		gulpTs := wallNs

		evtAction := "unknown"
		switch evtType {
		case 1:
			evtAction = "execve"
		case 2:
			evtAction = "connect_enter"
		case 3:
			evtAction = "accept_exit"
		}

		// attempt to parse optional network fields appended after filename
		// layout in C: after filename (offset 44 + 256 == 300) =>
		// family(2), sport(2), dport(2), saddr(4), daddr(4), saddr6(16), daddr6(16)
		var netInfo map[string]interface{}
		netBase := 44 + 256
		if len(raw) >= netBase+14 {
			family := binary.LittleEndian.Uint16(raw[netBase : netBase+2])
			sport := binary.LittleEndian.Uint16(raw[netBase+2 : netBase+4])
			dport := binary.LittleEndian.Uint16(raw[netBase+4 : netBase+6])

			// ipv4 addresses are stored starting at netBase+6 (4 bytes each)
			var saddrStr, daddrStr string
			if len(raw) >= netBase+14 {
				saddrBytes := raw[netBase+6 : netBase+10]
				daddrBytes := raw[netBase+10 : netBase+14]
				// bytes are copied as network-order bytes; format as dotted quad
				saddrStr = fmt.Sprintf("%d.%d.%d.%d", saddrBytes[0], saddrBytes[1], saddrBytes[2], saddrBytes[3])
				daddrStr = fmt.Sprintf("%d.%d.%d.%d", daddrBytes[0], daddrBytes[1], daddrBytes[2], daddrBytes[3])
			}

			// if ipv6 addresses present, parse into string form
			var saddr6Str, daddr6Str string
			if len(raw) >= netBase+14+16+16 {
				saddr6 := raw[netBase+14 : netBase+30]
				daddr6 := raw[netBase+30 : netBase+46]
				saddr6Str = net.IP(saddr6).String()
				daddr6Str = net.IP(daddr6).String()
			}

			// attach network info to event map when present
			if family != 0 {
				netInfo = map[string]interface{}{
					"network.family": int(family),
				}
				if saddrStr != "" {
					netInfo["network.saddr"] = saddrStr
				}
				if daddrStr != "" {
					netInfo["network.daddr"] = daddrStr
				}
				if saddr6Str != "" {
					netInfo["network.saddr6"] = saddr6Str
				}
				if daddr6Str != "" {
					netInfo["network.daddr6"] = daddr6Str
				}
				if sport != 0 {
					netInfo["network.sport"] = int(sport)
				}
				if dport != 0 {
					netInfo["network.dport"] = int(dport)
				}
			}
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

		// merge any parsed network info into the event
		if netInfo != nil {
			for k, v := range netInfo {
				e[k] = v
			}
		}

			dbg("ebpf event: ts=%s(tsMs=%d, gulpTs=%d) pid=%d tgid=%d uid=%d gid=%d evt_type=%d comm=%s filename=%s", ts, tsMs, gulpTs, pid, tgid, uid, gid, evtType, comm, filename)
			chunk = append(chunk, e)
			if len(chunk) >= cfg.MaxChunkSize {
				if err := sendPacket(ws, cfg, wsID, reqID, &chunk, false); err != nil {
					return err
				}
			}
		case err := <-readErrCh:
			// transient read error; wait briefly then continue. if context cancelled, exit.
			_ = err
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				_ = sendPacket(ws, cfg, wsID, reqID, &chunk, true)
				return nil
			default:
			}
		case <-ticker.C:
			if len(chunk) > 0 {
				if err := sendPacket(ws, cfg, wsID, reqID, &chunk, false); err != nil {
					return err
				}
			}
		}
	}
}

// monotonicNsToWallTime converts a monotonic timestamp (nanoseconds since
// boot, as produced by bpf_ktime_get_ns) to a wall-clock time.Time and the
// corresponding unix-nanoseconds value. It uses CLOCK_MONOTONIC to compute
// the system boot epoch and falls back to treating the input as unix time
// when CLOCK_MONOTONIC is unavailable.
func monotonicNsToWallTime(evtNs int64) (time.Time, int64) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		monoNow := ts.Sec*1e9 + int64(ts.Nsec)
		wallNow := time.Now().UnixNano()
		bootEpoch := wallNow - monoNow
		eventWallNs := bootEpoch + evtNs
		return time.Unix(0, eventWallNs).UTC(), eventWallNs
	}
	// fallback: treat evtNs as unix-ns (best-effort)
	return time.Unix(0, evtNs).UTC(), evtNs
}

// readEbpfEvents is a small wrapper used by the caller to start the reader.
func readEbpfEvents(ctx context.Context, bpfPath string, ws *WSClient, cfg *Config, wsID, reqID string, errCh chan<- error) {
	err := ebpfEventReader(ctx, bpfPath, ws, cfg, wsID, reqID)
	select {
	case errCh <- err:
	default:
	}
}

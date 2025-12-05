// CLEANED BY COPILOT: single-file ebpf reader implementation
package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"
)

// Event is a generic event shape we will send as raw data
type Event map[string]any

var globalSeq uint64

// matchPatternHelper is a recursive helper for glob-style pattern matching.
// supports * (matches any sequence) and ? (matches single character).
func matchPatternHelper(pattern, s string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// skip consecutive stars
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			// try matching remainder at each position
			for i := 0; i <= len(s); i++ {
				if matchPatternHelper(pattern, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			pattern = pattern[1:]
			s = s[1:]
		default:
			if len(s) == 0 || pattern[0] != s[0] {
				return false
			}
			pattern = pattern[1:]
			s = s[1:]
		}
	}
	return len(s) == 0
}

// shouldExcludeProcess checks if the executable matches any exclusion pattern.
func shouldExcludeProcess(executable string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPatternHelper(pattern, executable) {
			return true
		}
	}
	return false
}

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

	// simple cache for process info to avoid hitting /proc for every event
	type procInfo struct {
		name    string
		cmdline string
	}
	procCache := make(map[uint32]procInfo)

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
			var tsMs uint64
			var tgid uint32
			var uid uint32
			var gid uint32
			var evtType uint32
			var comm string
			var filename string
			raw := rec.RawSample
			if len(raw) >= 8 {
				tsMs = binary.LittleEndian.Uint64(raw[0:8])
			}
			if len(raw) >= 16 {
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

			// parse cmdline field (after filename, 4096 bytes)
			// format: args stored in fixed 128-byte slots (MAX_ARGS=32, ARG_LEN=128)
			// each slot contains a null-terminated string
			// struct layout: ts(8) + pid(4) + tgid(4) + uid(4) + gid(4) + evt_type(4) + comm(16) + filename(256) = 300
			var cmdline string
			cmdlineBase := 300 // offset after filename (8+4+4+4+4+4+16+256)
			cmdlineLen := 4096 // MAX_ARGS * ARG_LEN
			argLen := 128      // ARG_LEN - fixed size per argument slot
			maxArgs := 32      // MAX_ARGS

			if len(raw) >= cmdlineBase+argLen {
				end := cmdlineBase + cmdlineLen
				if end > len(raw) {
					end = len(raw)
				}
				cmdlineBytes := raw[cmdlineBase:end]

				// extract args from fixed-size slots and join with spaces
				var args []string
				for i := 0; i < maxArgs; i++ {
					slotStart := i * argLen
					slotEnd := slotStart + argLen
					if slotEnd > len(cmdlineBytes) {
						break
					}
					slot := cmdlineBytes[slotStart:slotEnd]
					// find null terminator in slot
					if nullIdx := bytes.IndexByte(slot, 0); nullIdx > 0 {
						args = append(args, string(slot[:nullIdx]))
					} else if nullIdx < 0 && len(slot) > 0 {
						// no null found, use whole slot
						args = append(args, string(slot))
					}
					// nullIdx == 0 means empty slot, stop
					if len(slot) == 0 || slot[0] == 0 {
						break
					}
				}
				cmdline = strings.Join(args, " ")
			}

			// Fallback: if cmdline or filename are empty (e.g. connect/accept events), try to fetch from /proc
			// Use cache to avoid excessive I/O
			var pInfo procInfo
			var found bool

			// If execve (evtType == 1), we must refresh because process identity changed.
			if evtType != 1 {
				pInfo, found = procCache[tgid]
			}

			if !found || evtType == 1 {
				// Try to read from /proc if eBPF data is missing
				// Note: eBPF data is apparently always empty per user report, so we rely on /proc
				newCmdline := cmdline
				newFilename := filename

				if newCmdline == "" {
					if procCmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", tgid)); err == nil {
						parts := bytes.Split(procCmdline, []byte{0})
						var args []string
						for _, p := range parts {
							if len(p) > 0 {
								args = append(args, string(p))
							}
						}
						newCmdline = strings.Join(args, " ")
					}
				}
				if newFilename == "" {
					if exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", tgid)); err == nil {
						newFilename = exePath
					}
				}

				// Update cache
				pInfo = procInfo{name: newFilename, cmdline: newCmdline}
				procCache[tgid] = pInfo

				// Simple eviction if cache grows too large
				if len(procCache) > 10000 {
					// Clear cache completely to avoid complexity of LRU
					procCache = make(map[uint32]procInfo)
				}
			}

			cmdline = pInfo.cmdline
			filename = pInfo.name

			seq := atomic.AddUint64(&globalSeq, 1)
			// convert bpf monotonic ms to wall-clock time
			evtNs := int64(tsMs) * 1_000_000
			wallT, wallNs := monotonicNsToWallTime(evtNs)
			ts := wallT.Format(time.RFC3339)
			gulpTs := wallNs

			evtAction := "unknown"
			switch evtType {
			case 1:
				evtAction = "proc_exec"
			case 2:
				evtAction = "conn_outbound"
			case 3:
				evtAction = "conn_inbound"
			case 4:
				evtAction = "login"
			}

			// attempt to parse optional network fields appended after cmdline
			// layout in C: after cmdline (offset 300 + 4096 == 4396) =>
			// family(2), sport(2), dport(2), __pad(2), saddr(4), daddr(4), saddr6(16), daddr6(16)
			var netInfo map[string]interface{}
			netBase := 4396 // 300 (cmdline offset) + 4096 (cmdline size)

			// read family if present
			if len(raw) >= netBase+2 {
				family := binary.LittleEndian.Uint16(raw[netBase : netBase+2])
				if family != 0 {
					netInfo = map[string]interface{}{"network.family": int(family)}

					// try to read ports (sport,dport) if present
					if len(raw) >= netBase+6 {
						sport := binary.LittleEndian.Uint16(raw[netBase+2 : netBase+4])
						dport := binary.LittleEndian.Uint16(raw[netBase+4 : netBase+6])
						if sport != 0 {
							netInfo["network.sport"] = int(sport)
						}
						if dport != 0 {
							netInfo["network.dport"] = int(dport)
						}
					}

					// ipv4 addresses (saddr,daddr) - skip 2 bytes padding after dport
					if len(raw) >= netBase+16 {
						saddrBytes := raw[netBase+8 : netBase+12]
						daddrBytes := raw[netBase+12 : netBase+16]
						saddrStr := fmt.Sprintf("%d.%d.%d.%d", saddrBytes[0], saddrBytes[1], saddrBytes[2], saddrBytes[3])
						daddrStr := fmt.Sprintf("%d.%d.%d.%d", daddrBytes[0], daddrBytes[1], daddrBytes[2], daddrBytes[3])
						// only add non-zero addresses
						if !(saddrBytes[0] == 0 && saddrBytes[1] == 0 && saddrBytes[2] == 0 && saddrBytes[3] == 0) {
							netInfo["network.saddr"] = saddrStr
						}
						if !(daddrBytes[0] == 0 && daddrBytes[1] == 0 && daddrBytes[2] == 0 && daddrBytes[3] == 0) {
							netInfo["network.daddr"] = daddrStr
						}
					}

					// ipv6 addresses (offset 16 for saddr6, 32 for daddr6)
					if len(raw) >= netBase+48 {
						saddr6 := raw[netBase+16 : netBase+32]
						daddr6 := raw[netBase+32 : netBase+48]
						// ignore all-zero ipv6
						zero6 := true
						for i := 0; i < 16; i++ {
							if saddr6[i] != 0 {
								zero6 = false
								break
							}
						}
						if !zero6 {
							netInfo["network.saddr6"] = net.IP(saddr6).String()
						}
						zero6 = true
						for i := 0; i < 16; i++ {
							if daddr6[i] != 0 {
								zero6 = false
								break
							}
						}
						if !zero6 {
							netInfo["network.daddr6"] = net.IP(daddr6).String()
						}
					}
				}
			}

			// compute gulp.event_code as fnv hash of evtAction
			h := fnv.New32a()
			h.Write([]byte(evtAction))
			eventCode := int(h.Sum32())

			// determine process name from cmdline (first argument, basename) or fallback to comm
			// cmdline contains space-separated arguments; if empty, fall back to filename
			processName := comm
			processCmdline := cmdline
			if cmdline != "" && strings.TrimSpace(cmdline) != "" {
				// first argument is the executable path
				parts := strings.SplitN(strings.TrimSpace(cmdline), " ", 2)
				if len(parts) > 0 && parts[0] != "" {
					processName = filepath.Base(parts[0])
				}
			} else if filename != "" {
				// fallback: use filename if available
				processName = filepath.Base(filename)
				processCmdline = filename
			}

			// check if process should be excluded based on executable pattern
			if len(cfg.ProcessExclude) > 0 && shouldExcludeProcess(processName, cfg.ProcessExclude) {
				dbg("excluding process by pattern: %s", processName)
				continue
			}

			// event original is just a dummy placeholder here (every information is already structured into fields)
			eventOriginal := "-"

			e := Event{
				"@timestamp":           ts,
				"gulp.timestamp":       gulpTs,
				"gulp.operation_id":    cfg.Gulp.OperationID,
				"gulp.context_id":      contextID,
				"gulp.source_id":       sourceID,
				"agent.type":           "slurp_ebpf",
				"event.original":       eventOriginal,
				"event.sequence":       int(seq),
				"event.code":           evtAction,
				"gulp.event_code":      eventCode,
				"event.duration":       1,
				"process.name":         processName,
				"process.command_line": processCmdline,
				"process.pid":          tgid,
				"user.uid":             int(uid),
				"user.gid":             int(gid),
				"host.hostname":        osHostnameOrEmpty(),
			}

			// merge any parsed network info into the event
			if netInfo != nil {
				for k, v := range netInfo {
					e[k] = v
				}
			}

			// compute _id as sha256 hash of the event content
			eventBytes, _ := json.Marshal(e)
			idHash := sha256.Sum256(eventBytes)
			e["_id"] = hex.EncodeToString(idHash[:])

			dbg("parsed event: %v", e)

			// append to chunk
			chunk = append(chunk, e)
			if len(chunk) >= cfg.MaxChunkSize {
				// threshold reached; send chunk
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

func osHostnameOrEmpty() string {
	hn, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hn
}

// buildContextIDs computes context/source ids from hostname
func buildContextIDs() (string, string) {
	hn, _ := os.Hostname()
	h := sha1.Sum([]byte(hn))
	hexh := hex.EncodeToString(h[:])
	// use full sha1 hex as context_id and source_id
	return hexh, hexh
}

// readEbpfEvents is a small wrapper used by the caller to start the reader.
func readEbpfEvents(ctx context.Context, bpfPath string, ws *WSClient, cfg *Config, wsID, reqID string, errCh chan<- error) {
	err := ebpfEventReader(ctx, bpfPath, ws, cfg, wsID, reqID)
	select {
	case errCh <- err:
	default:
	}
}

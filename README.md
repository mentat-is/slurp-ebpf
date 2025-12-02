# slurp-ebpf

Small Go program that logs into Gulp, opens the `/ws_ingest_raw` websocket and streams eBPF events in chunks.

Usage:

1. Edit `slurp_cfg.json` with your `gulp.uri`, `gulp.username`, and `gulp.password`.
2. Optionally add hooks (list of hook names) to `hooks` — if empty the program generates mock events for testing.
3. Build and run:

```bash
go build -o slurp-ebpf .
./slurp-ebpf -config slurp_cfg.json
```

Notes:
- This version uses a mock eBPF event producer when no hooks are configured. Integrating real eBPF readers requires adding BPF programs/maps and reading from perf ring buffers.
2. Build the BPF object:

```bash
./build_bpf.sh
```

This will produce `slurp_bpf.o`. The program automatically tries to load `./slurp_bpf.o` (or the path in `bpf_object` in the config) and will stream real kernel events from the `sys_enter_execve` tracepoint.

3. Build and run the agent:

```bash
go build -o slurp-ebpf .
./slurp-ebpf -config slurp_cfg.json
```

Notes:
- The BPF program `slurp_bpf.c` writes a binary event struct to a perf events map named `events`.
- The Go program reads perf samples and will try to interpret JSON if present; otherwise it wraps raw samples.

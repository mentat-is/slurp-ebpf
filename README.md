# slurp-ebpf

logs into Gulp, opens the `/ws_ingest_raw` websocket and streams eBPF events in chunks.

Usage:

1. Edit `slurp_cfg.json` with your `gulp.uri`, `gulp.username`, `gulp.password`, `gulp.operation_id` and optionally add hooks (list of hook names) to `hooks` (either defaults are applied)
2. Build and run:

```bash
# install prerequisites:
# sudo pacman -S llvm bpf clang libelf linux-headers 
./build_and_run.sh
```

This will compile the [ebpf program](./bpf/slurp_ebpf.c) to produce `slurp_ebpf.o` and the `slurp-ebpf` go binary. 

The program automatically tries to load `./slurp_ebpf.o` (or the path in `bpf_object` in the config) and will stream kernel events from the defined hooks.


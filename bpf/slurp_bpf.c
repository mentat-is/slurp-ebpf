// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <bpf/bpf_core_read.h>

struct event {
    __u64 ts_ms;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 evt_type;
    char comm[16];
    char filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__sys_enter_execve(void *ctx)
{
    struct event e = {};
    e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = (uint32_t)pid_tgid;
    e.tgid = (uint32_t)(pid_tgid >> 32);
    __u64 uid_gid = bpf_get_current_uid_gid();
    e.uid = (uint32_t)uid_gid;
    e.gid = (uint32_t)(uid_gid >> 32);
    e.evt_type = 1; /* execve */
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    // tracepoint args: first argument is filename pointer
    void *args = ctx;
    // Using CO-RE read for tracepoint args[0]
    const char *filename_ptr = NULL;
    bpf_core_read(&filename_ptr, sizeof(filename_ptr), ((char *)args) + 8);
    if (filename_ptr) {
        bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename_ptr);
    }

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}

    SEC("tracepoint/syscalls/sys_enter_openat")
    int tracepoint__sys_enter_openat(void *ctx)
    {
        struct event e = {};
        e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        e.pid = (uint32_t)pid_tgid;
        e.tgid = (uint32_t)(pid_tgid >> 32);
        __u64 uid_gid = bpf_get_current_uid_gid();
        e.uid = (uint32_t)uid_gid;
        e.gid = (uint32_t)(uid_gid >> 32);
        e.evt_type = 2; /* openat enter */
        bpf_get_current_comm(&e.comm, sizeof(e.comm));

        void *args = ctx;
        const char *filename_ptr = NULL;
        /* tracepoint args layout: dfd (int), filename (const char *) ... */
        bpf_core_read(&filename_ptr, sizeof(filename_ptr), ((char *)args) + 8);
        if (filename_ptr) {
            bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename_ptr);
        }

        bpf_ringbuf_output(&events, &e, sizeof(e), 0);
        return 0;
    }

    SEC("tracepoint/syscalls/sys_exit_openat")
    int tracepoint__sys_exit_openat(void *ctx)
    {
        struct event e = {};
        e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        e.pid = (uint32_t)pid_tgid;
        e.tgid = (uint32_t)(pid_tgid >> 32);
        __u64 uid_gid = bpf_get_current_uid_gid();
        e.uid = (uint32_t)uid_gid;
        e.gid = (uint32_t)(uid_gid >> 32);
        e.evt_type = 3; /* openat exit */
        bpf_get_current_comm(&e.comm, sizeof(e.comm));

        bpf_ringbuf_output(&events, &e, sizeof(e), 0);
        return 0;
    }

    SEC("kprobe/do_sys_open")
    int kprobe__do_sys_open(void *ctx)
    {
        struct event e = {};
        e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        e.pid = (uint32_t)pid_tgid;
        e.tgid = (uint32_t)(pid_tgid >> 32);
        __u64 uid_gid = bpf_get_current_uid_gid();
        e.uid = (uint32_t)uid_gid;
        e.gid = (uint32_t)(uid_gid >> 32);
        e.evt_type = 4; /* do_sys_open kprobe */
        bpf_get_current_comm(&e.comm, sizeof(e.comm));

        /* Skip reading filename here for portability; user can rely on exec/openat tracepoints for filenames */
        bpf_ringbuf_output(&events, &e, sizeof(e), 0);
        return 0;
    }

char LICENSE[] SEC("license") = "GPL";

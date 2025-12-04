// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <bpf/bpf_core_read.h>
/* for AF_INET/AF_INET6 constants */
#include <sys/socket.h>
#include <linux/in.h>

struct event {
    __u64 ts_ms;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 evt_type;
    char comm[16];
    char filename[256];
    /* network fields (ipv4 only for now) */
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
    /* ipv6 addresses (if family == AF_INET6) */
    __u8 saddr6[16];
    __u8 daddr6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/*
 * tracepoint: sys_enter_execve
 * description: capture process metadata and the filename argument when a
 * process calls execve. emits `struct event` to the ringbuf with
 * evt_type == 1.
 */
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

    /*
     * tracepoint args: first argument is filename pointer. use co-re read
     * to access the tracepoint argument pointer then read the user string
     * from user-space into the event filename buffer.
     */
    void *args = ctx;
    const char *filename_ptr = NULL;
    bpf_core_read(&filename_ptr, sizeof(filename_ptr), ((char *)args) + 8);
    if (filename_ptr) {
        /* read user-space filename string into event */
        bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename_ptr);
    }

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}

/*
 * tracepoint: sys_enter_connect
 * description: capture the destination sockaddr user pointer passed to
 * connect(2). attempts to read an IPv4 sockaddr and store dst ip/port
 * in the event (evt_type == 5). network-order port is converted to host
 * byte order.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__sys_enter_connect(void *ctx)
{
    struct event e = {};
    e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = (uint32_t)pid_tgid;
    e.tgid = (uint32_t)(pid_tgid >> 32);
    __u64 uid_gid = bpf_get_current_uid_gid();
    e.uid = (uint32_t)uid_gid;
    e.gid = (uint32_t)(uid_gid >> 32);
    e.evt_type = 2; /* connect enter */
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    /* read sockaddr pointer from tracepoint args; arg layout can vary */
    void *args = ctx;
    const void *addr_ptr = NULL;
    bpf_core_read(&addr_ptr, sizeof(addr_ptr), ((char *)args) + 16);
    if (!addr_ptr) {
        /* fallback offset if tracepoint layout differs */
        bpf_core_read(&addr_ptr, sizeof(addr_ptr), ((char *)args) + 8);
    }

    /* buffer to hold sockaddr_in/sa data; ipv4 sockaddr_in is 16 bytes */
    unsigned char sa[28] = {};
    if (addr_ptr) {
        /* read user-space sockaddr into local buffer */
        if (bpf_probe_read_user(&sa, sizeof(sa), addr_ptr) == 0) {
            __u16 fam = 0;
            __builtin_memcpy(&fam, &sa[0], sizeof(fam));
            e.family = fam;
            if (fam == AF_INET) {
                __u16 port_be = 0;
                __builtin_memcpy(&port_be, &sa[2], sizeof(port_be));
                /* convert network byte order to host */
                e.dport = (port_be >> 8) | (port_be << 8);
                /* copy ipv4 address (network order) into event */
                __builtin_memcpy(&e.daddr, &sa[4], sizeof(e.daddr));
            } else if (fam == AF_INET6) {
                __u16 port_be = 0;
                /* in sockaddr_in6 port is at offset 2 */
                __builtin_memcpy(&port_be, &sa[2], sizeof(port_be));
                e.dport = (port_be >> 8) | (port_be << 8);
                /* ipv6 address begins at offset 8 in sockaddr_in6 */
                __builtin_memcpy(&e.daddr6, &sa[8], sizeof(e.daddr6));
            }
        }
    }

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}

/*
 * tracepoint: sys_exit_accept
 * description: on accept(2) exit, the kernel has populated the user
 * provided sockaddr with the client's address. this handler attempts to
 * read an IPv4 sockaddr and fill source ip/port in the event (evt_type == 6).
 */
SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__sys_exit_accept(void *ctx)
{
    struct event e = {};
    e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e.pid = (uint32_t)pid_tgid;
    e.tgid = (uint32_t)(pid_tgid >> 32);
    __u64 uid_gid = bpf_get_current_uid_gid();
    e.uid = (uint32_t)uid_gid;
    e.gid = (uint32_t)(uid_gid >> 32);
    e.evt_type = 3; /* accept exit */
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    /* read sockaddr pointer from tracepoint args; kernel wrote client addr */
    void *args = ctx;
    const void *addr_ptr = NULL;
    bpf_core_read(&addr_ptr, sizeof(addr_ptr), ((char *)args) + 16);
    if (!addr_ptr) {
        bpf_core_read(&addr_ptr, sizeof(addr_ptr), ((char *)args) + 8);
    }

    unsigned char sa[28] = {};
    if (addr_ptr) {
        /* copy user-space sockaddr into local buffer */
        if (bpf_probe_read_user(&sa, sizeof(sa), addr_ptr) == 0) {
            __u16 fam = 0;
            __builtin_memcpy(&fam, &sa[0], sizeof(fam));
            e.family = fam;
            if (fam == AF_INET) {
                __u16 port_be = 0;
                __builtin_memcpy(&port_be, &sa[2], sizeof(port_be));
                e.sport = (port_be >> 8) | (port_be << 8);
                __builtin_memcpy(&e.saddr, &sa[4], sizeof(e.saddr));
            } else if (fam == AF_INET6) {
                __u16 port_be = 0;
                __builtin_memcpy(&port_be, &sa[2], sizeof(port_be));
                e.sport = (port_be >> 8) | (port_be << 8);
                /* ipv6 address begins at offset 8 in sockaddr_in6 */
                __builtin_memcpy(&e.saddr6, &sa[8], sizeof(e.saddr6));
            }
        }
    }

    bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    return 0;
}

    // /*
    //  * tracepoint: sys_enter_openat
    //  * description: capture process metadata and the filename argument when
    //  * openat is entered. emits `struct event` to the ringbuf with
    //  * evt_type == 2.
    //  */
    // SEC("tracepoint/syscalls/sys_enter_openat")
    // int tracepoint__sys_enter_openat(void *ctx)
    // {
    //     struct event e = {};
    //     e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    //     __u64 pid_tgid = bpf_get_current_pid_tgid();
    //     e.pid = (uint32_t)pid_tgid;
    //     e.tgid = (uint32_t)(pid_tgid >> 32);
    //     __u64 uid_gid = bpf_get_current_uid_gid();
    //     e.uid = (uint32_t)uid_gid;
    //     e.gid = (uint32_t)(uid_gid >> 32);
    //     e.evt_type = 2; /* openat enter */
    //     bpf_get_current_comm(&e.comm, sizeof(e.comm));

    //     /* read filename argument from tracepoint args (dfd, filename, ...) */
    //     void *args = ctx;
    //     const char *filename_ptr = NULL;
    //     bpf_core_read(&filename_ptr, sizeof(filename_ptr), ((char *)args) + 8);
    //     if (filename_ptr) {
    //         /* copy filename string from user-space */
    //         bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename_ptr);
    //     }

    //     bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    //     return 0;
    // }

    // /*
    //  * tracepoint: sys_exit_openat
    //  * description: capture process metadata on openat exit. this event does
    //  * not include filename (already captured on enter) and is used to signal
    //  * completion of the openat syscall (evt_type == 3).
    //  */
    // SEC("tracepoint/syscalls/sys_exit_openat")
    // int tracepoint__sys_exit_openat(void *ctx)
    // {
    //     struct event e = {};
    //     e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    //     __u64 pid_tgid = bpf_get_current_pid_tgid();
    //     e.pid = (uint32_t)pid_tgid;
    //     e.tgid = (uint32_t)(pid_tgid >> 32);
    //     __u64 uid_gid = bpf_get_current_uid_gid();
    //     e.uid = (uint32_t)uid_gid;
    //     e.gid = (uint32_t)(uid_gid >> 32);
    //     e.evt_type = 3; /* openat exit */
    //     bpf_get_current_comm(&e.comm, sizeof(e.comm));

    //     bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    //     return 0;
    // }

    // /*
    //  * kprobe: do_sys_open
    //  * description: lightweight kprobe that records an open syscall event.
    //  * filename is intentionally not read here for portability; use the
    //  * execve/openat tracepoints for filenames.
    //  */
    // SEC("kprobe/do_sys_open")
    // int kprobe__do_sys_open(void *ctx)
    // {
    //     struct event e = {};
    //     e.ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    //     __u64 pid_tgid = bpf_get_current_pid_tgid();
    //     e.pid = (uint32_t)pid_tgid;
    //     e.tgid = (uint32_t)(pid_tgid >> 32);
    //     __u64 uid_gid = bpf_get_current_uid_gid();
    //     e.uid = (uint32_t)uid_gid;
    //     e.gid = (uint32_t)(uid_gid >> 32);
    //     e.evt_type = 4; /* do_sys_open kprobe */
    //     bpf_get_current_comm(&e.comm, sizeof(e.comm));

    //     /* skip reading filename here for portability; rely on tracepoints for names */
    //     bpf_ringbuf_output(&events, &e, sizeof(e), 0);
    //     return 0;
    // }

char LICENSE[] SEC("license") = "GPL";

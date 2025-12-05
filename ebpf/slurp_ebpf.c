// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2
#define AF_INET6 10

#define MAX_ARGS 32
#define ARG_LEN 128
#define CMDLINE_LEN (MAX_ARGS * ARG_LEN)

struct event {
    __u64 ts_ms;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 evt_type;
    char comm[16];
    char filename[256];
    char cmdline[CMDLINE_LEN];
    // network fields
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u16 __pad;
    __u32 saddr;
    __u32 daddr;
    __u8 saddr6[16];
    __u8 daddr6[16];
};

struct execve_data {
    char filename[256];
    char args[MAX_ARGS][ARG_LEN];
    __u8 arg_count;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} accept_sockaddr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct execve_data);
} execve_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct execve_data);
} execve_args SEC(".maps");

// Helpers
static __always_inline struct event *get_event(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&event_heap, &zero);
}

static __always_inline struct execve_data *get_execve_data(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&execve_heap, &zero);
}

// Tracepoint helpers
#define TP_READ_ARG(ctx, offset, type) \
    ({ type __val; bpf_probe_read_kernel(&__val, sizeof(__val), (void *)ctx + offset); __val; })

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__sys_enter_execve(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 filename_ptr = TP_READ_ARG(ctx, 16, __u64);
    __u64 argv_ptr = TP_READ_ARG(ctx, 24, __u64);

    if (!filename_ptr) return 0;

    struct execve_data *data = get_execve_data();
    if (!data) return 0;

    // Clear data
    __builtin_memset(data->filename, 0, sizeof(data->filename));
    data->arg_count = 0;
    // We don't memset args to save cycles, we just ensure null termination when reading

    // Read filename
    long ret = bpf_probe_read_user_str(data->filename, sizeof(data->filename), (const char *)filename_ptr);
    if (ret <= 0) {
        // Fallback for kernel threads or weird contexts
        bpf_probe_read_kernel_str(data->filename, sizeof(data->filename), (const char *)filename_ptr);
    }

    // Read args
    if (argv_ptr) {
        #pragma unroll
        for (int i = 0; i < MAX_ARGS; i++) {
            const char *arg_ptr = NULL;
            // Calculate address of the pointer: argv_ptr + i * 8
            // We use __u64 for arithmetic to avoid pointer confusion
            __u64 ptr_addr = argv_ptr + (i * 8);
            
            // Read the pointer value
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), (void *)ptr_addr) != 0) {
                 if (bpf_probe_read_kernel(&arg_ptr, sizeof(arg_ptr), (void *)ptr_addr) != 0) {
                     // If we can't read the pointer, we can't read the arg.
                     break; 
                 }
            }
            
            if (!arg_ptr) break; // NULL pointer indicates end of argv

            // Read the string
            long len = bpf_probe_read_user_str(data->args[i], ARG_LEN, arg_ptr);
            if (len <= 0) {
                 len = bpf_probe_read_kernel_str(data->args[i], ARG_LEN, arg_ptr);
            }
            
            if (len > 0) {
                data->arg_count++;
            } else {
                data->args[i][0] = 0;
            }
        }
    }

    bpf_map_update_elem(&execve_args, &pid_tgid, data, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__sys_exit_execve(void *ctx)
{
    long ret = TP_READ_ARG(ctx, 16, long);
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Always clean up the map entry
    struct execve_data *data = bpf_map_lookup_elem(&execve_args, &pid_tgid);
    if (!data) return 0;

    if (ret != 0) {
        bpf_map_delete_elem(&execve_args, &pid_tgid);
        return 0;
    }

    struct event *e = get_event();
    if (!e) {
        bpf_map_delete_elem(&execve_args, &pid_tgid);
        return 0;
    }

    // Initialize event
    e->ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->evt_type = 1; // execve
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Zero network fields
    e->family = 0; e->sport = 0; e->dport = 0; e->__pad = 0;
    e->saddr = 0; e->daddr = 0;
    __builtin_memset(e->saddr6, 0, 16);
    __builtin_memset(e->daddr6, 0, 16);

    // Copy data
    __builtin_memcpy(e->filename, data->filename, sizeof(e->filename));
    
    // Manually copy args to avoid memcpy issues with large buffers or verifier
    // Since both are char arrays, we can use bpf_probe_read_kernel which is safe
    bpf_probe_read_kernel(e->cmdline, sizeof(e->cmdline), data->args);

    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    bpf_map_delete_elem(&execve_args, &pid_tgid);
    return 0;
}

// fallback tracepoint to catch exec events that may not be observed via
// syscall tracepoints (covers execveat and other exec paths). this emits
// a lightweight exec event so user-space can read /proc to populate
// filename/cmdline when needed.
SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(void *ctx)
{
    struct event *e = get_event();
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->evt_type = 1; // execve-like
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // keep filename/cmdline empty; user-space will read /proc/<pid>/exe
    // and /proc/<pid>/cmdline when it sees evt_type == 1
    e->filename[0] = 0;
    e->cmdline[0] = 0;

    // zero network fields
    e->family = 0; e->sport = 0; e->dport = 0; e->__pad = 0;
    e->saddr = 0; e->daddr = 0;
    __builtin_memset(e->saddr6, 0, 16);
    __builtin_memset(e->daddr6, 0, 16);

    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__sys_enter_connect(void *ctx)
{
    struct event *e = get_event();
    if (!e) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    
    e->ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->evt_type = 2; // connect
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = 0;
    e->cmdline[0] = 0;
    
    // Network fields
    e->family = 0; e->sport = 0; e->dport = 0; e->__pad = 0;
    e->saddr = 0; e->daddr = 0;
    __builtin_memset(e->saddr6, 0, 16);
    __builtin_memset(e->daddr6, 0, 16);

    void *addr_ptr = TP_READ_ARG(ctx, 24, void *);
    if (addr_ptr) {
        unsigned char sa[28] = {};
        if (bpf_probe_read_user(&sa, sizeof(sa), addr_ptr) == 0) {
            __u16 fam = *(__u16*)&sa[0];
            e->family = fam;
            if (fam == 2) { // AF_INET
                e->dport = (__u16)((sa[2] << 8) | sa[3]);
                e->daddr = *(__u32*)&sa[4];
            } else if (fam == 10) { // AF_INET6
                e->dport = (__u16)((sa[2] << 8) | sa[3]);
                __builtin_memcpy(e->daddr6, &sa[8], 16);
            }
        }
    }

    // Filter empty or non-IP
    if (e->family != AF_INET && e->family != AF_INET6) return 0;

    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint__sys_enter_accept(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 addr_ptr = TP_READ_ARG(ctx, 24, __u64);
    if (addr_ptr) {
        bpf_map_update_elem(&accept_sockaddr, &pid_tgid, &addr_ptr, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__sys_exit_accept(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *addr_ptr_val = bpf_map_lookup_elem(&accept_sockaddr, &pid_tgid);
    if (!addr_ptr_val) return 0;

    void *addr_ptr = (void *)*addr_ptr_val;
    bpf_map_delete_elem(&accept_sockaddr, &pid_tgid);

    struct event *e = get_event();
    if (!e) return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    e->ts_ms = bpf_ktime_get_ns() / 1000000ULL;
    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid = (__u32)uid_gid;
    e->gid = (__u32)(uid_gid >> 32);
    e->evt_type = 3; // accept
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = 0;
    e->cmdline[0] = 0;

    e->family = 0; e->sport = 0; e->dport = 0; e->__pad = 0;
    e->saddr = 0; e->daddr = 0;
    __builtin_memset(e->saddr6, 0, 16);
    __builtin_memset(e->daddr6, 0, 16);

    if (addr_ptr) {
        unsigned char sa[28] = {};
        if (bpf_probe_read_user(&sa, sizeof(sa), addr_ptr) == 0) {
            __u16 fam = *(__u16*)&sa[0];
            e->family = fam;
            if (fam == 2) { // AF_INET
                e->sport = (__u16)((sa[2] << 8) | sa[3]);
                e->saddr = *(__u32*)&sa[4];
            } else if (fam == 10) { // AF_INET6
                e->sport = (__u16)((sa[2] << 8) | sa[3]);
                __builtin_memcpy(e->saddr6, &sa[8], 16);
            }
        }
    }

    if (e->family != AF_INET && e->family != AF_INET6) return 0;

    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

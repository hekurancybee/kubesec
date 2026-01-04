// SPDX-License-Identifier: GPL-2.0
// KubeSec - Syscall tracer for Kubernetes workload protection
// Captures syscalls with arguments for file access, execution, and network operations

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_COMM_LEN 16
#define MAX_ARG_LEN 128

// Minimal network types to avoid header conflicts
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct in_addr {
    unsigned int s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct in_addr sin_addr;
    char sin_zero[8];
};

// Manual syscall defines as fallback if asm/unistd.h is problematic
#if defined(__TARGET_ARCH_x86)
    #ifndef __NR_openat
    #define __NR_openat     257
    #endif
    #ifndef __NR_execve
    #define __NR_execve     59
    #endif
    #ifndef __NR_execveat
    #define __NR_execveat   322
    #endif
    #ifndef __NR_connect
    #define __NR_connect    42
    #endif
    #ifndef __NR_bind
    #define __NR_bind       49
    #endif
    #ifndef __NR_unlinkat
    #define __NR_unlinkat   263
    #endif
    #ifndef __NR_mknodat
    #define __NR_mknodat    259
    #endif
#elif defined(__TARGET_ARCH_arm64)
    #ifndef __NR_openat
    #define __NR_openat     56
    #endif
    #ifndef __NR_execve
    #define __NR_execve     221
    #endif
    #ifndef __NR_execveat
    #define __NR_execveat   281
    #endif
    #ifndef __NR_connect
    #define __NR_connect    203
    #endif
    #ifndef __NR_bind
    #define __NR_bind       200
    #endif
    #ifndef __NR_unlinkat
    #define __NR_unlinkat   35
    #endif
    #ifndef __NR_mknodat
    #define __NR_mknodat    33
    #endif
#endif

// Syscall event structure sent to userspace
struct syscall_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u64 cgroup_id;
    __s64 syscall_nr;
    char comm[MAX_COMM_LEN];
    char arg_str[MAX_ARG_LEN];
} __attribute__((packed));

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Map to track which cgroups (containers) we're monitoring
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u8);
} target_cgroups SEC(".maps");

// Map for blocked syscalls (cgroup_id, syscall_nr) -> block
// Deprecated in favor of granular allowlist
struct key_t {
    __u64 cgroup_id;
    __u32 syscall_nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct key_t);
    __type(value, __u8);
} blocked_syscalls SEC(".maps");

// Granular allowlist (cgroup_id, syscall_nr, arg_str) -> allowed
struct allowlist_key {
    __u64 cgroup_id;
    __u32 syscall_nr;
    char arg_str[MAX_ARG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct allowlist_key);
    __type(value, __u8);
} allowed_syscalls SEC(".maps");

// Prefix-based allowlist using LPM Trie
struct prefix_key {
    __u32 prefixlen;
    __u64 cgroup_id;
    __u32 syscall_nr;
    char path[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct prefix_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_prefixes SEC(".maps");

// Enforcement mode (cgroup_id) -> 1 (enforcement), 0 (training)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u8);
} enforcement_mode SEC(".maps");

// Scratchpad for allowlist keys to avoid stack limit issues
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct allowlist_key);
} akey_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct prefix_key);
} pkey_scratch SEC(".maps");


SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    struct syscall_event *event;
    __u64 cgroup_id;
    __u8 *target;
    __s64 syscall_nr;

    // Get cgroup ID (used to identify containers)
    cgroup_id = bpf_get_current_cgroup_id();

    // Check if this cgroup is a target we're monitoring
    target = bpf_map_lookup_elem(&target_cgroups, &cgroup_id);
    if (!target) {
        return 0;
    }

    // Get syscall number
    syscall_nr = ctx->args[1];

    // Check if this syscall is blocked (legacy blocklist)
    struct key_t key;
    __builtin_memset(&key, 0, sizeof(key));
    key.cgroup_id = cgroup_id;
    key.syscall_nr = (__u32)syscall_nr;
    
    __u8 *blocked = bpf_map_lookup_elem(&blocked_syscalls, &key);
    if (blocked) {
        bpf_send_signal(9);
    }

    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill basic event data
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->cgroup_id = cgroup_id;
    event->syscall_nr = syscall_nr;
    
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memset(event->arg_str, 0, sizeof(event->arg_str));

    // Capture arguments for security-relevant syscalls
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    
    switch (syscall_nr) {
    case __NR_openat: {
        // openat(int dirfd, const char *pathname, int flags, mode_t mode)
        // pathname is 2nd argument
        const char *pathname = (const char *)PT_REGS_PARM2_CORE(regs);
        bpf_probe_read_user_str(event->arg_str, sizeof(event->arg_str), pathname);
        break;
    }
    
    case __NR_execve: {
        // execve(const char *pathname, char *const argv[], char *const envp[])
        // pathname is 1st argument
        const char *pathname = (const char *)PT_REGS_PARM1_CORE(regs);
        bpf_probe_read_user_str(event->arg_str, sizeof(event->arg_str), pathname);
        break;
    }
    
    case __NR_execveat: {
        // execveat(int dirfd, const char *pathname, ...)
        // pathname is 2nd argument
        const char *pathname = (const char *)PT_REGS_PARM2_CORE(regs);
        bpf_probe_read_user_str(event->arg_str, sizeof(event->arg_str), pathname);
        break;
    }
    
    case __NR_connect:
    case __NR_bind: {
        // connect/bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        // addr is 2nd argument
        struct sockaddr *addr = (struct sockaddr *)PT_REGS_PARM2_CORE(regs);
        if (addr) {
            __u16 family;
            bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
            
            // Only capture IPv4 for now (AF_INET = 2)
            if (family == 2) {
                struct sockaddr_in sin;
                bpf_probe_read_user(&sin, sizeof(sin), addr);
                
                // Format IP:port into arg_str
                __u32 ip = sin.sin_addr.s_addr;
                __u16 port = __builtin_bswap16(sin.sin_port);
                
                // Simple IP formatting
                int pos = 0;
                
                // IP octets
                __u8 o1 = (ip >> 0) & 0xFF;
                __u8 o2 = (ip >> 8) & 0xFF;
                __u8 o3 = (ip >> 16) & 0xFF;
                __u8 o4 = (ip >> 24) & 0xFF;
                
                // Format: "X.X.X.X:XXXXX"
                if (o1 >= 100) event->arg_str[pos++] = '0' + o1/100;
                if (o1 >= 10) event->arg_str[pos++] = '0' + (o1/10)%10;
                event->arg_str[pos++] = '0' + o1%10;
                event->arg_str[pos++] = '.';
                
                if (o2 >= 100) event->arg_str[pos++] = '0' + o2/100;
                if (o2 >= 10) event->arg_str[pos++] = '0' + (o2/10)%10;
                event->arg_str[pos++] = '0' + o2%10;
                event->arg_str[pos++] = '.';
                
                if (o3 >= 100) event->arg_str[pos++] = '0' + o3/100;
                if (o3 >= 10) event->arg_str[pos++] = '0' + (o3/10)%10;
                event->arg_str[pos++] = '0' + o3%10;
                event->arg_str[pos++] = '.';
                
                if (o4 >= 100) event->arg_str[pos++] = '0' + o4/100;
                if (o4 >= 10) event->arg_str[pos++] = '0' + (o4/10)%10;
                event->arg_str[pos++] = '0' + o4%10;
                event->arg_str[pos++] = ':';
                
                if (port >= 10000) event->arg_str[pos++] = '0' + port/10000;
                if (port >= 1000) event->arg_str[pos++] = '0' + (port/1000)%10;
                if (port >= 100) event->arg_str[pos++] = '0' + (port/100)%10;
                if (port >= 10) event->arg_str[pos++] = '0' + (port/10)%10;
                event->arg_str[pos++] = '0' + port%10;
            }
        }
        break;
    }
    
    case __NR_unlinkat: {
        // unlinkat(int dirfd, const char *pathname, int flags)
        // pathname is 2nd argument
        const char *pathname = (const char *)PT_REGS_PARM2_CORE(regs);
        bpf_probe_read_user_str(event->arg_str, sizeof(event->arg_str), pathname);
        break;
    }
    
    case __NR_mknodat: {
        // mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
        // pathname is 2nd argument
        const char *pathname = (const char *)PT_REGS_PARM2_CORE(regs);
        bpf_probe_read_user_str(event->arg_str, sizeof(event->arg_str), pathname);
        break;
    }
    
    default:
        // No argument capture for other syscalls
        break;
    }

    // Kernel-side enforcement using granular allowlist
    __u8 *mode = bpf_map_lookup_elem(&enforcement_mode, &cgroup_id);
    if (mode && *mode == 1) {
        __u32 zero = 0;
        struct allowlist_key *akey = bpf_map_lookup_elem(&akey_scratch, &zero);
        if (akey) {
            __builtin_memset(akey, 0, sizeof(*akey));
            akey->cgroup_id = cgroup_id;
            akey->syscall_nr = (__u32)syscall_nr;
            __builtin_memcpy(akey->arg_str, event->arg_str, sizeof(akey->arg_str));
            
            __u8 *allowed = bpf_map_lookup_elem(&allowed_syscalls, akey);
            if (!allowed) {
                // If not in exact match allowlist, check LPM prefix allowlist
                struct prefix_key *pkey = bpf_map_lookup_elem(&pkey_scratch, &zero);
                if (pkey) {
                    __builtin_memset(pkey, 0, sizeof(*pkey));
                    pkey->prefixlen = (8 + 4 + 128) * 8; // Full length for lookup
                    pkey->cgroup_id = cgroup_id;
                    pkey->syscall_nr = (__u32)syscall_nr;
                    __builtin_memcpy(pkey->path, event->arg_str, sizeof(pkey->path));

                    allowed = bpf_map_lookup_elem(&allowed_prefixes, pkey);
                    if (!allowed) {
                        // Syscall is NOT in allowlist - kill it
                        bpf_send_signal(9);
                    }
                }
            }
        }
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

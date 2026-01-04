// Package ebpf provides the eBPF syscall tracer
package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include" -target arm64 syscallTracer ../../bpf/syscall_tracer.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include" -target amd64 syscallTracer ../../bpf/syscall_tracer.bpf.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// SyscallEvent represents a syscall event from the eBPF program
type SyscallEvent struct {
	TimestampNs uint64
	Pid         uint32
	Tgid        uint32
	CgroupID    uint64
	SyscallNr   int64
	Comm        [16]byte
	ArgStr      [128]byte // Captured string argument (file path, IP:port, etc.)
}

// Tracer manages the eBPF syscall tracer
type Tracer struct {
	objs              syscallTracerObjects
	link              link.Link
	reader            *ringbuf.Reader
	syscallMap        map[int64]string
	reverseSyscallMap map[string]int64
}

// GlobalAllowlist contains syscalls that are always allowed and not logged to ClickHouse.
// These are typically noisy, essential syscalls for process lifecycle and memory management.
var GlobalAllowlist = map[string]bool{
	"exit":            true,
	"exit_group":      true,
	"rt_sigreturn":    true,
	"rt_sigprocmask":  true,
	"rt_sigaction":    true,
	"rt_sigsuspend":   true,
	"sigaltstack":     true,
	"futex":           true,
	"brk":             true,
	"mmap":            true,
	"munmap":          true,
	"mprotect":        true,
	"getpid":          true,
	"gettid":          true,
	"getuid":          true,
	"getgid":          true,
	"geteuid":         true,
	"getegid":         true,
	"gettimeofday":    true,
	"clock_gettime":   true,
	"time":            true,
	"nanosleep":       true,
	"sched_yield":     true,
	"close":           true,
	"fcntl":           true,
	"ioctl":           true,
	"read":            true,
	"write":           true,
	"lseek":           true,
	"pread64":         true,
	"pwrite64":        true,
	"readv":           true,
	"writev":          true,
	"dup":             true,
	"dup2":            true,
	"dup3":            true,
	"pipe":            true,
	"pipe2":           true,
	"select":          true,
	"poll":            true,
	"ppoll":           true,
	"pselect6":        true,
	"epoll_wait":      true,
	"epoll_pwait":     true,
	"epoll_ctl":       true,
	"epoll_create":    true,
	"epoll_create1":   true,
	"rt_sigpending":   true,
	"rt_sigtimedwait": true,
	"statfs":          true,
	"fstatfs":         true,
	"newfstatat":      true,
	"fstatat":         true,
	"getdents64":      true,
	"uname":           true,
}

// IsGlobalAllowlisted returns true if the syscall is in the global allowlist.
func (t *Tracer) IsGlobalAllowlisted(syscallName string) bool {
	return GlobalAllowlist[syscallName]
}

// NewTracer creates a new syscall tracer
func NewTracer() (*Tracer, error) {
	// Load pre-compiled eBPF program
	objs := syscallTracerObjects{}
	if err := loadSyscallTracerObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	// Attach to raw tracepoint
	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: objs.SysEnter,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	archMap := GetArchSyscallMap()
	reverseMap := make(map[string]int64)
	for nr, name := range archMap {
		reverseMap[name] = nr
	}

	t := &Tracer{
		objs:              objs,
		link:              tp,
		reader:            reader,
		syscallMap:        archMap,
		reverseSyscallMap: reverseMap,
	}

	return t, nil
}

// AddTargetCgroup adds a cgroup ID to monitor
func (t *Tracer) AddTargetCgroup(cgroupID uint64) error {
	val := uint8(1)
	return t.objs.TargetCgroups.Put(cgroupID, val)
}

// RemoveTargetCgroup removes a cgroup ID from monitoring
func (t *Tracer) RemoveTargetCgroup(cgroupID uint64) error {
	return t.objs.TargetCgroups.Delete(cgroupID)
}

// BlockSyscall adds a syscall to the block list for a specific cgroup
// Deprecated: Use AllowSyscall and EnableEnforcement instead
func (t *Tracer) BlockSyscall(cgroupID uint64, syscallNr int) error {
	key := syscallTracerKeyT{
		CgroupId:  cgroupID,
		SyscallNr: uint32(syscallNr),
	}
	val := uint8(1)
	return t.objs.BlockedSyscalls.Put(key, val)
}

// EnableEnforcement enables kernel-side enforcement for a cgroup
func (t *Tracer) EnableEnforcement(cgroupID uint64) error {
	val := uint8(1)
	return t.objs.EnforcementMode.Put(cgroupID, val)
}

// DisableEnforcement disables kernel-side enforcement for a cgroup
func (t *Tracer) DisableEnforcement(cgroupID uint64) error {
	return t.objs.EnforcementMode.Delete(cgroupID)
}

// AllowSyscall adds a syscall to the kernel-side allowlist for a cgroup
func (t *Tracer) AllowSyscall(cgroupID uint64, syscallNr int, argument string) error {
	key := syscallTracerAllowlistKey{
		CgroupId:  cgroupID,
		SyscallNr: uint32(syscallNr),
	}

	// Copy argument string to ArgStr [128]int8
	for i := 0; i < len(argument) && i < 128; i++ {
		key.ArgStr[i] = int8(argument[i])
	}

	val := uint8(1)
	return t.objs.AllowedSyscalls.Put(key, val)
}

// AllowPrefix adds a prefix-based rule to the kernel-side LPM trie for a cgroup.
func (t *Tracer) AllowPrefix(cgroupID uint64, syscallNr int, prefix string) error {
	// LPM Trie keys in eBPF must have prefixlen as first 32 bits.
	// The prefixlen is the number of bits in the key to match.
	// Our key data is: cgroup_id (64 bits) + syscall_nr (32 bits) + path (128 * 8 bits)
	key := syscallTracerPrefixKey{
		Prefixlen: uint32(8+4)*8 + uint32(len(prefix))*8,
		CgroupId:  cgroupID,
		SyscallNr: uint32(syscallNr),
	}

	// Copy prefix string to Path [128]int8
	for i := 0; i < len(prefix) && i < 128; i++ {
		key.Path[i] = int8(prefix[i])
	}

	val := uint8(1)
	return t.objs.AllowedPrefixes.Put(key, val)
}

// DenySyscall removes a syscall from the kernel-side allowlist for a cgroup.
func (t *Tracer) DenySyscall(cgroupID uint64, syscallNr int, argument string) error {
	key := syscallTracerAllowlistKey{
		CgroupId:  cgroupID,
		SyscallNr: uint32(syscallNr),
	}
	for i := 0; i < len(argument) && i < 128; i++ {
		key.ArgStr[i] = int8(argument[i])
	}
	return t.objs.AllowedSyscalls.Delete(key)
}

// DenyPrefix removes a prefix-based rule from the kernel-side LPM trie for a cgroup.
func (t *Tracer) DenyPrefix(cgroupID uint64, syscallNr int, prefix string) error {
	key := syscallTracerPrefixKey{
		Prefixlen: uint32(8+4)*8 + uint32(len(prefix))*8,
		CgroupId:  cgroupID,
		SyscallNr: uint32(syscallNr),
	}
	for i := 0; i < len(prefix) && i < 128; i++ {
		key.Path[i] = int8(prefix[i])
	}
	return t.objs.AllowedPrefixes.Delete(key)
}

// GetSyscallNr returns the syscall number for a given name on the current architecture.
func (t *Tracer) GetSyscallNr(name string) (int, error) {
	// 1. Check if it's already a number string (e.g. "syscall_123" or "123")
	if strings.HasPrefix(name, "syscall_") {
		var nr int
		_, err := fmt.Sscanf(name, "syscall_%d", &nr)
		if err == nil {
			return nr, nil
		}
	}

	// 2. Lookup in our architecture-aware reverse map
	if nr, ok := t.reverseSyscallMap[name]; ok {
		return int(nr), nil
	}

	return 0, fmt.Errorf("unknown syscall: %s", name)
}

// ReadEvent reads the next syscall event from the ring buffer
func (t *Tracer) ReadEvent() (*SyscallEvent, error) {
	record, err := t.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("reading from ring buffer: %w", err)
	}

	var event SyscallEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return nil, fmt.Errorf("parsing event: %w", err)
	}

	return &event, nil
}

// GetSyscallName returns the name of a syscall by number
func (t *Tracer) GetSyscallName(nr int64) string {
	if name, ok := t.syscallMap[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

func (t *Tracer) Close() error {
	t.reader.Close()
	t.link.Close()
	return t.objs.Close()
}

// GetCgroupIDForPID returns the cgroup ID for a given PID
func GetCgroupIDForPID(pid int) (uint64, error) {
	// Read cgroup path from /proc/{pid}/cgroup
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, fmt.Errorf("reading cgroup: %w", err)
	}

	// Parse cgroup path - we need the cgroup v2 path
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			// cgroup v2 entry
			cgroupPath := "/sys/fs/cgroup" + parts[2]

			// Get cgroup ID using name_to_handle_at
			var handle unix.FileHandle
			var mountID int

			handle, mountID, err = unix.NameToHandleAt(unix.AT_FDCWD, cgroupPath, 0)
			if err != nil {
				return 0, fmt.Errorf("getting cgroup handle: %w", err)
			}
			_ = mountID

			// The file handle contains the cgroup ID
			if len(handle.Bytes()) >= 8 {
				return binary.LittleEndian.Uint64(handle.Bytes()[:8]), nil
			}
		}
	}

	return 0, fmt.Errorf("cgroup v2 not found for pid %d", pid)
}

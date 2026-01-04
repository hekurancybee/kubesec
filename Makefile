# KubeSec - Kubernetes Syscall Security Agent
# Makefile for building eBPF programs and Go agent

CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(ARCH_INC)
BPF_SRC := bpf/syscall_tracer.bpf.c
BPF_OBJ := bpf/syscall_tracer.bpf.o

LIBBPF_HEADERS := /home/parallels/Development/EBPF/network_tunnel/bpftool/libbpf/src

.PHONY: all clean build generate ebpf

all: ebpf generate build

# Compile eBPF program
ebpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I$(LIBBPF_HEADERS) \
		-c $(BPF_SRC) \
		-o $(BPF_OBJ)

# Generate Go bindings from eBPF object
generate: $(BPF_OBJ)
	cd pkg/ebpf && go generate

# Build the Go agent
build:
	$(GO) build -o bin/kubesec-agent ./cmd/agent

# Run the agent (requires root)
run: build
	sudo ./bin/kubesec-agent

# Clean build artifacts
clean:
	rm -f $(BPF_OBJ)
	rm -f pkg/ebpf/syscalltracer_*.go pkg/ebpf/syscalltracer_*.o
	rm -rf bin/

# Install dependencies
deps:
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

# Verify eBPF program
verify: $(BPF_OBJ)
	llvm-objdump -d $(BPF_OBJ)

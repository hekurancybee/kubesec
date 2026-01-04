// KubeSec Agent - Syscall-based workload protection for Kubernetes
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubesec/kubesec/pkg/engine"
)

func main() {
	// Parse flags
	clickhouseHost := flag.String("clickhouse", "localhost", "ClickHouse host")
	clickhousePort := flag.Int("clickhouse-port", 9000, "ClickHouse port")
	serverMode := flag.Bool("server", false, "Run in API Server mode (disable eBPF tracing)")
	flag.Parse()

	log.Println("KubeSec Agent - Syscall Protection")
	log.Println("===================================")

	if *serverMode {
		log.Println("Mode: Server (Tracing Disabled)")
	} else {
		log.Println("Mode: Agent (Tracing Enabled)")
		// Check for root privileges only in Agent mode
		if os.Geteuid() != 0 {
			log.Fatal("This program requires root privileges. Please run with sudo.")
		}
	}

	// Create engine
	cfg := engine.Config{
		ClickHouseHost: *clickhouseHost,
		ClickHousePort: *clickhousePort,
		EnableTracing:  !*serverMode,
	}

	eng, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create engine: %v", err)
	}

	// Start engine
	if err := eng.Start(); err != nil {
		log.Fatalf("Failed to start engine: %v", err)
	}

	log.Println("Engine started. Watching for syscalls...")
	log.Println("  - Workloads with icu.systems/secure: 'true' will be protected")
	log.Println("  - Training period from icu.systems/training-period (default: 24h)")
	log.Println("")

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	eng.Stop()
	log.Println("Shutdown complete.")
}

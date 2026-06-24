package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/karandesai2005/ebpf-agent/internal/dpi"
	"github.com/karandesai2005/ebpf-agent/internal/opa"
	"github.com/karandesai2005/ebpf-agent/internal/tetragon"
)

func main() {
	log.Println("🚀 krato — eBPF security agent starting...")

	// Load OPA engine with Rego policies
	engine, err := opa.NewEngine("./policies")
	if err != nil {
		log.Fatalf("failed to load OPA policies: %v", err)
	}
	log.Println("✅ OPA policies loaded")

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Ctrl+C handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\n🛑 shutting down...")
		cancel()
	}()

	// Start DPI monitor in background goroutine
	// This hooks tcp_sendmsg at kernel level and scans payloads for GitHub PATs
	go func() {
		err := dpi.Monitor(func(pid uint32, comm string, payload string) {
			// Truncate payload for display
			displayPayload := payload
			if len(displayPayload) > 200 {
				displayPayload = displayPayload[:200] + "..."
			}

			fmt.Printf("\n\033[31m\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")
			fmt.Printf("   \033[31m\033[1m🔑 CRITICAL — GitHub PAT EXFILTRATION DETECTED\033[0m\n")
			fmt.Printf("\033[31m\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")
			fmt.Printf("   PID:     %d\n", pid)
			fmt.Printf("   Process: %s\n", comm)
			fmt.Printf("   Payload: \033[33m%s\033[0m\n", displayPayload)
			fmt.Printf("\033[31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n")
		})
		if err != nil {
			log.Printf("⚠️  DPI monitor error: %v", err)
		}
	}()

	// Create Tetragon listener for process detection
	listener := tetragon.NewListener("localhost:54321", engine)

	// Start listening — blocks forever until Ctrl+C
	if err := listener.Start(ctx); err != nil {
		log.Printf("listener stopped: %v", err)
	}
}
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	// Create Tetragon listener
	listener := tetragon.NewListener("localhost:54321", engine)

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

	// Start listening — blocks forever until Ctrl+C
	if err := listener.Start(ctx); err != nil {
		log.Printf("listener stopped: %v", err)
	}
}
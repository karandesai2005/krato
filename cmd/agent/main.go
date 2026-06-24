package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/karandesai2005/ebpf-agent/internal/dpi"
	"github.com/karandesai2005/ebpf-agent/internal/opa"
	"github.com/karandesai2005/ebpf-agent/internal/tetragon"
)

const policiesDir = "./policies"

func main() {
	log.Println("🚀 krato — eBPF security agent starting...")

	engine, err := opa.NewEngine(policiesDir)
	if err != nil {
		log.Fatalf("failed to load OPA policies: %v", err)
	}
	log.Println("✅ OPA policies loaded")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("\n🛑 shutting down...")
		cancel()
	}()

	go watchPolicies(ctx, policiesDir, engine)

	go func() {
		err := dpi.Monitor(func(pid uint32, comm string, payload string) {
			displayPayload := payload
			if len(displayPayload) > 200 {
				displayPayload = displayPayload[:200]
			}

			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println("🔑 CRITICAL — GitHub PAT EXFILTRATION DETECTED")
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Printf("PID:     %d\n", pid)
			fmt.Printf("Process: %s\n", comm)
			fmt.Printf("Payload: %s\n", displayPayload)
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		})
		if err != nil {
			log.Printf("⚠️  DPI monitor unavailable: %v", err)
		}
	}()

	listener := tetragon.NewListener("localhost:54321", engine)
	if err := listener.Start(ctx); err != nil {
		log.Printf("listener stopped: %v", err)
	}
}

func watchPolicies(ctx context.Context, dir string, engine *opa.Engine) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("⚠️  policy watcher unavailable: %v", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		log.Printf("⚠️  failed to watch policies dir: %v", err)
		return
	}

	var debounce *time.Timer

	for {
		select {
		case <-ctx.Done():
			if debounce != nil {
				debounce.Stop()
			}
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
				continue
			}
			if !strings.HasSuffix(event.Name, ".rego") {
				continue
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(500*time.Millisecond, func() {
				if err := engine.Reload(); err != nil {
					log.Printf("⚠️  policy reload failed: %v", err)
					return
				}
				log.Printf("🔄 policies reloaded — %d rules active", engine.RuleCount())
			})

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("⚠️  policy watcher error: %v", err)
		}
	}
}
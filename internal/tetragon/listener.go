package tetragon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	tetragonAPI "github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/karandesai2005/ebpf-agent/internal/opa"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Listener connects to Tetragon gRPC and processes events
type Listener struct {
	addr   string
	engine *opa.Engine
}

// NewListener creates a new listener
func NewListener(addr string, engine *opa.Engine) *Listener {
	return &Listener{
		addr:   addr,
		engine: engine,
	}
}

// Start connects and streams events
func (l *Listener) Start(ctx context.Context) error {
	conn, err := grpc.NewClient(
		l.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to tetragon at %s: %w", l.addr, err)
	}
	defer conn.Close()

	log.Printf("✅ Connected to Tetragon at %s", l.addr)

	client := tetragonAPI.NewFineGuidanceSensorsClient(conn)

	stream, err := client.GetEvents(ctx, &tetragonAPI.GetEventsRequest{})
	if err != nil {
		return fmt.Errorf("failed to open event stream: %w", err)
	}
	log.Println("👁️  Listening for kernel events...\n")

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Listener shutting down...")
			return nil
		default:
		}

		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream closed: %w", err)
		}

		l.handleEvent(event)
	}
}

// handleEvent processes each Tetragon event
func (l *Listener) handleEvent(event *tetragonAPI.GetEventsResponse) {
	input := buildInput(event)
	if input == nil {
		return
	}

	var query string
	switch input["type"] {
	case "process_exec":
		query = "agent.process.deny"
	case "network_connect":
		query = "agent.network.deny"
	default:
		return
	}

	results, err := l.engine.Evaluate(query, input)
	if err != nil {
		log.Printf("OPA error: %v", err)
		return
	}

	if len(results) > 0 {
		printAlert(input, results)
	} else {
		printClean(input)
	}
}

// buildInput converts protobuf → OPA-friendly map
func buildInput(event *tetragonAPI.GetEventsResponse) map[string]interface{} {
	switch e := event.Event.(type) {

	case *tetragonAPI.GetEventsResponse_ProcessExec:
		exec := e.ProcessExec
		if exec.Process == nil {
			return nil
		}

		parentName := ""
		parentPID := uint32(0)
		if exec.Parent != nil {
			parentName = exec.Parent.Binary
			parentPID = exec.Parent.Pid.Value
		}

		var namespace, podName, containerName string
		if exec.Process.Pod != nil {
			namespace = exec.Process.Pod.Namespace
			podName = exec.Process.Pod.Name
			if exec.Process.Pod.Container != nil {
				containerName = exec.Process.Pod.Container.Name
			}
		}

		return map[string]interface{}{
			"type": "process_exec",
			"process": map[string]interface{}{
				"binary":      exec.Process.Binary,
				"arguments":   exec.Process.Arguments,
				"pid":         float64(exec.Process.Pid.Value),
				"uid":         float64(exec.Process.Uid.Value),
				"parent_name": parentName,
				"parent_pid":  float64(parentPID),
			},
			"container": map[string]interface{}{
				"namespace": namespace,
				"pod_name":  podName,
				"name":      containerName,
			},
		}

	case *tetragonAPI.GetEventsResponse_ProcessKprobe:
		kprobe := e.ProcessKprobe
		if kprobe.Process == nil {
			return nil
		}

		var namespace, podName string
		if kprobe.Process.Pod != nil {
			namespace = kprobe.Process.Pod.Namespace
			podName = kprobe.Process.Pod.Name
		}

		destIP := ""
		destPort := float64(0)
		payload := ""

		for _, arg := range kprobe.Args {
			switch v := arg.Arg.(type) {
			case *tetragonAPI.KprobeArgument_SockaddrArg:
				if sa := v.SockaddrArg; sa != nil {
					destIP = sa.GetAddr()      // Fixed
					destPort = float64(sa.GetPort()) // Fixed
				}
			case *tetragonAPI.KprobeArgument_BytesArg:
				if len(v.BytesArg) > 0 {
					payload = string(v.BytesArg)
				}
			}
		}

		return map[string]interface{}{
			"type": "network_connect",
			"process": map[string]interface{}{
				"binary": kprobe.Process.Binary,
				"pid":    float64(kprobe.Process.Pid.Value),
			},
			"network": map[string]interface{}{
				"dest_ip":   destIP,
				"dest_port": destPort,
				"payload":   payload,
			},
			"container": map[string]interface{}{
				"namespace": namespace,
				"pod_name":  podName,
			},
		}
	}

	return nil
}

// printAlert prints violation
func printAlert(input map[string]interface{}, messages []string) {
	eventType := input["type"].(string)

	fmt.Println()
	fmt.Println("🚨 \033[31m\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
	fmt.Printf("   \033[31m\033[1mALERT — %s\033[0m\n", eventType)
	fmt.Println("🚨 \033[31m\033[1m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")

	for _, msg := range messages {
		fmt.Printf("   → %s\n", msg)
	}

	if proc, ok := input["process"].(map[string]interface{}); ok {
		fmt.Printf("   binary:  %v\n", proc["binary"])
		if parent, ok := proc["parent_name"].(string); ok && parent != "" {
			fmt.Printf("   parent:  %s\n", parent)
		}
		fmt.Printf("   uid:     %v\n", proc["uid"])
	}

	if container, ok := input["container"].(map[string]interface{}); ok {
		if pod, ok := container["pod_name"].(string); ok && pod != "" {
			fmt.Printf("   pod:     %s/%s\n", container["namespace"], pod)
		}
	}

	if raw, err := json.MarshalIndent(input, "   ", "  "); err == nil {
		fmt.Printf("\n   raw event:\n%s\n", string(raw))
	}

	fmt.Println("\033[31m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m")
}

// printClean prints allowed events (low noise)
func printClean(input map[string]interface{}) {
	proc, ok := input["process"].(map[string]interface{})
	if !ok {
		return
	}
	binary, _ := proc["binary"].(string)
	if binary == "" {
		return
	}

	container, _ := input["container"].(map[string]interface{})
	namespace, _ := container["namespace"].(string)
	podName, _ := container["pod_name"].(string)

	if podName != "" {
		fmt.Printf("\033[32m[CLEAN]\033[0m  %s/%s → %s\n", namespace, podName, binary)
	}
}
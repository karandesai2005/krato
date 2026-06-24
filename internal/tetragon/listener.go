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

// Listener connects to Tetragon gRPC and processes events.
type Listener struct {
	addr   string
	engine *opa.Engine
}

func NewListener(addr string, engine *opa.Engine) *Listener {
	return &Listener{
		addr:   addr,
		engine: engine,
	}
}

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

func (l *Listener) handleEvent(event *tetragonAPI.GetEventsResponse) {
	input := buildInput(event)
	if input == nil {
		return
	}

	var query string
	switch input["type"] {
	case "process_exec":
		query = "agent.process.violation"
	case "network_connect":
		query = "agent.network.violation"
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

func buildInput(event *tetragonAPI.GetEventsResponse) map[string]interface{} {
	switch e := event.Event.(type) {

	case *tetragonAPI.GetEventsResponse_ProcessExec:
		exec := e.ProcessExec
		if exec == nil {
			return nil
		}

		proc := exec.Process
		if proc == nil {
			return nil
		}

		ns := ""
		podName := ""
		containerName := ""
		if proc.Pod != nil {
			ns = proc.Pod.Namespace
			podName = proc.Pod.Name
			if proc.Pod.Container != nil {
				containerName = proc.Pod.Container.Name
			}
		}

		parentName := ""
		parentPID := uint32(0)
		if exec.Parent != nil {
			parentName = exec.Parent.Binary
			if exec.Parent.Pid != nil {
				parentPID = exec.Parent.Pid.Value
			}
		}

		return map[string]interface{}{
			"type": "process_exec",
			"process": map[string]interface{}{
				"binary":      proc.Binary,
				"arguments":   proc.Arguments,
				"pid":         getPid(proc),
				"uid":         getUid(proc),
				"parent_name": parentName,
				"parent_pid":  float64(parentPID),
			},
			"container": map[string]interface{}{
				"namespace": ns,
				"pod_name":  podName,
				"name":      containerName,
			},
		}

	case *tetragonAPI.GetEventsResponse_ProcessKprobe:
		kprobe := e.ProcessKprobe
		if kprobe == nil || kprobe.Process == nil {
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
					destIP = sa.GetAddr()
					destPort = float64(sa.GetPort())
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
				"pid":    float64(kprobe.Process.Pid.GetValue()),
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

func getPid(p *tetragonAPI.Process) float64 {
	if p != nil && p.Pid != nil {
		return float64(p.Pid.Value)
	}
	return 0
}

func getUid(p *tetragonAPI.Process) float64 {
	if p != nil && p.Uid != nil {
		return float64(p.Uid.Value)
	}
	return 0
}

func severityStyle(severity string) string {
	switch severity {
	case "CRITICAL":
		return "\033[91m\033[1m"
	case "HIGH":
		return "\033[31m"
	case "MEDIUM":
		return "\033[33m"
	default:
		return "\033[31m"
	}
}

func highestSeverity(violations []opa.Violation) string {
	order := map[string]int{
		"CRITICAL": 3,
		"HIGH":     2,
		"MEDIUM":   1,
	}
	best := ""
	bestRank := 0
	for _, v := range violations {
		rank := order[v.Severity]
		if rank > bestRank {
			bestRank = rank
			best = v.Severity
		}
	}
	if best == "" {
		return "HIGH"
	}
	return best
}

func printAlert(input map[string]interface{}, violations []opa.Violation) {
	eventType := input["type"].(string)
	topSeverity := highestSeverity(violations)
	style := severityStyle(topSeverity)

	fmt.Println()
	fmt.Printf("🚨 %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n", style)
	fmt.Printf("   %sALERT — %s [%s]\033[0m\n", style, eventType, topSeverity)
	fmt.Printf("🚨 %s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n", style)

	for _, v := range violations {
		msgStyle := severityStyle(v.Severity)
		fmt.Printf("   %s[%s]\033[0m → %s\n", msgStyle, v.Severity, v.Msg)
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

	fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n", style)
}

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
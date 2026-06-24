# krato

> eBPF-powered runtime security agent for Kubernetes.  
> Detects malicious processes and secret exfiltration — before a CVE exists.

```
kernel syscall → Tetragon eBPF → Go agent → OPA Rego rules → alert
```

---

## What it does

Krato hooks into the Linux kernel via **Tetragon** and watches every process spawn and network connection inside your Kubernetes cluster. Every event is evaluated against **OPA Rego policies** — human-readable rules that fire alerts without touching Go code.

Three detection layers:

**Process detection**
- Shell spawned inside a container (`/bin/bash`, `/bin/sh` inside nginx, node, python)
- Network tools (`curl`, `wget`, `nc`) executed by app processes
- Container escape attempts (`nsenter`, `unshare`, `chroot`)
- Privilege escalation binaries run as root
- Crypto miner signatures

**Deep packet inspection**
- GitHub PAT (`ghp_*`) detected in outbound payload to non-GitHub IP
- AWS credentials (`AKIA*`, `ASIA*`) in network traffic
- Generic secret patterns (`"token":`, `Authorization: Bearer`) to suspicious destinations
- Kubernetes metadata API access (`169.254.169.254`) — classic credential theft vector

**Rule-based via OPA Rego**
- Add new detection rules by dropping a `.rego` file — zero code changes
- Rules are plain text, human-readable, auditable
- Hot-reload supported at runtime

---

## Architecture

<img width="805" height="741" alt="image" src="https://github.com/user-attachments/assets/5acda02e-f8b0-48dd-961a-6b552ea34402" />

---

## How deep packet inspection works

### Plaintext HTTP — syscall hooking
Krato hooks `sys_write()` via Tetragon kprobes. When a process writes data to a network socket, Tetragon captures the buffer. The Go agent passes that buffer to OPA which scans for secret patterns (`ghp_`, `AKIA`, etc).

### Encrypted HTTPS — SSL uprobe
For TLS traffic, krato attaches a **uprobe** to `SSL_write` in `libssl.so`. This function is called with plaintext data *before* encryption. Tetragon captures the plaintext buffer at that point — same pattern matching, zero decryption needed.

This is the same technique used by Pixie and Hubble for encrypted traffic inspection.

---

## Why OPA Rego

Hardcoded detection logic means every new rule requires a code change, rebuild, and redeploy.

With Rego, adding a detection rule is five lines:

```rego
deny[msg] {
    input.process.binary == "/usr/bin/nmap"
    msg := sprintf("Port scanner in pod [%s]", [input.container.pod_name])
}
```

Drop the file. Agent picks it up. No rebuild.

Security teams can write and audit rules without touching Go. Rules are version-controlled, diff-able, and reviewable like any other code.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| eBPF runtime | Tetragon by Cilium |
| Agent language | Go 1.22 |
| Policy engine | OPA + Rego |
| Cluster | Kubernetes (Kind for local dev) |
| Package manager | Helm |

---

## Setup

**Prerequisites:** Linux (kernel 5.8+ with BTF), Docker, Go 1.22+, kubectl, Helm, Kind

```bash
# 1. Create Kind cluster
kind create cluster --name ebpf-agent

# 2. Install Tetragon
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status daemonset/tetragon -n kube-system

# 3. Verify Tetragon is capturing events
kubectl logs -n kube-system <tetragon-pod> -c export-stdout | head -20

# 4. Clone and run
git clone https://github.com/karandesai2005/krato
cd krato
go mod tidy
go run ./cmd/agent/main.go
```

---

## Project structure

```
krato/
├── cmd/agent/
│   └── main.go                 ← entry point
├── internal/
│   ├── tetragon/
│   │   └── listener.go         ← gRPC event stream
│   ├── opa/
│   │   └── engine.go           ← loads .rego files, evaluates events
│   └── alert/
│       └── alerter.go          ← colored terminal output
├── policies/
│   ├── process.rego            ← malicious process rules
│   └── network.rego            ← DPI + secret exfiltration rules
└── k8s/
    ├── kind-config.yaml        ← Kind cluster config
    └── tetragon-policy.yaml    ← TracingPolicy CRDs
```

---

## Detection rules

### process.rego

| Rule | Trigger | Severity |
|------|---------|----------|
| Shell in container | `/bin/bash`, `/bin/sh` spawned inside running pod | HIGH |
| Network tool from app | `curl`/`wget`/`nc` by `nginx`, `node`, `python` | HIGH |
| Container escape | `nsenter`, `unshare`, `chroot` | CRITICAL |
| Privilege escalation | `sudo`, `su`, `pkexec` as root | HIGH |
| Crypto miner | `xmrig`, `minerd` signatures | HIGH |

### network.rego

| Rule | Trigger | Severity |
|------|---------|----------|
| GitHub PAT exfiltration | `ghp_*` in payload to non-GitHub IP | CRITICAL |
| AWS credential leak | `AKIA*`/`ASIA*` in outbound traffic | CRITICAL |
| Secret patterns | `token`, `password`, `api_key` to suspicious IPs | HIGH |
| Metadata API access | Connection to `169.254.169.254` | CRITICAL |
| C2 high port | Outbound to port >9000 on external IP | MEDIUM |

---

## Sample alert output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [CRITICAL ALERT]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Time:      2026-06-23 16:52:20
  Event:     network_connect
  Message:   GitHub PAT detected in outbound payload
             to non-GitHub IP [185.220.101.47:4444]
             from pod [production/api-pod-xyz789]
  Dest IP:   185.220.101.47
  Dest Port: 4444
  Payload:   POST /collect {"token":"ghp_ABC..."}
  Pod:       api-pod-xyz789
  Namespace: production
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## What I'd add next

- Real Tetragon gRPC proto client (`FineGuidanceSensorsClient`)
- Full HTTPS DPI via `SSL_write` uprobe on libssl
- Threat intel feed — pull known bad IPs from OTX/MISP into Rego
- Slack / PagerDuty alerting webhooks
- Web dashboard with real-time alert feed
- Policy hot-reload via inotify
- eBPF ring buffer optimization (`BPF_MAP_TYPE_RINGBUF`)

---

## References

- [Tetragon Documentation](https://tetragon.io/docs/)
- [OPA Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [eBPF.io](https://ebpf.io)
- [Cilium TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/)
- Rohit Kumar — Rootconf talk on eBPF-based supply chain threat detection

---

*Built as part of an O3 Security engineering assessment.*  
*Author: [Karan Desai](https://karan-desai.vercel.app)*

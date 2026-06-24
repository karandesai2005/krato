package agent.network

import future.keywords.if

# Rule 1 — GitHub PAT going to non-GitHub destination (active exfiltration)
violation[v] if {
    input.type == "network_connect"
    input.container.pod_name != ""
    regex.match(`ghp_[A-Za-z0-9]{36}`, input.network.payload)
    not startswith(input.network.dest_ip, "140.82.")
    not startswith(input.network.dest_ip, "192.30.")
    not startswith(input.network.dest_ip, "185.199.")
    v := {
        "severity": "CRITICAL",
        "msg": sprintf(
            "🚨 EXFILTRATION — GitHub PAT sent to non-GitHub host %s (pod: %s/%s)",
            [input.network.dest_ip,
             input.container.namespace, input.container.pod_name]
        ),
    }
}

# Rule 2 — GitHub PAT in outbound payload
violation[v] if {
    input.type == "network_connect"
    input.container.pod_name != ""
    regex.match(`ghp_[A-Za-z0-9]{36}`, input.network.payload)
    v := {
        "severity": "HIGH",
        "msg": sprintf(
            "🔑 GitHub PAT detected in outbound traffic → %s:%v (pod: %s/%s)",
            [input.network.dest_ip, input.network.dest_port,
             input.container.namespace, input.container.pod_name]
        ),
    }
}

# Rule 3 — AWS Access Key in payload
violation[v] if {
    input.type == "network_connect"
    input.container.pod_name != ""
    regex.match(`AKIA[0-9A-Z]{16}`, input.network.payload)
    v := {
        "severity": "CRITICAL",
        "msg": sprintf(
            "🔑 AWS Access Key detected in outbound traffic → %s (pod: %s/%s)",
            [input.network.dest_ip,
             input.container.namespace, input.container.pod_name]
        ),
    }
}

# Rule 4 — Generic Bearer token exfiltration
violation[v] if {
    input.type == "network_connect"
    input.container.pod_name != ""
    regex.match(`Authorization: Bearer [A-Za-z0-9\-._~+/]+=*`, input.network.payload)
    v := {
        "severity": "MEDIUM",
        "msg": sprintf(
            "🔑 Bearer token in outbound request → %s:%v (pod: %s/%s)",
            [input.network.dest_ip, input.network.dest_port,
             input.container.namespace, input.container.pod_name]
        ),
    }
}
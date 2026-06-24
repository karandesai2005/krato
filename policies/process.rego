package agent.process

import future.keywords.if

# Rule 1a — shell spawned in production namespace
violation[v] if {
    input.type == "process_exec"
    input.container.pod_name != ""
    shell_binary(input.process.binary)
    input.container.namespace == "production"
    v := {
        "severity": "CRITICAL",
        "msg": sprintf(
            "Shell spawned in production pod [%s/%s] — binary: %s parent: %s",
            [input.container.namespace, input.container.pod_name,
             input.process.binary, input.process.parent_name]
        ),
    }
}

# Rule 1b — shell spawned in any other namespace
violation[v] if {
    input.type == "process_exec"
    input.container.pod_name != ""
    shell_binary(input.process.binary)
    input.container.namespace != "production"
    v := {
        "severity": "HIGH",
        "msg": sprintf(
            "Shell spawned in pod [%s/%s] — binary: %s parent: %s",
            [input.container.namespace, input.container.pod_name,
             input.process.binary, input.process.parent_name]
        ),
    }
}

shell_binary(b) if b == "/bin/bash"
shell_binary(b) if b == "/bin/sh"
shell_binary(b) if b == "/usr/bin/bash"
shell_binary(b) if b == "/usr/bin/sh"

# Rule 2 — network tool spawned by app process inside a container
violation[v] if {
    input.type == "process_exec"
    input.container.pod_name != ""
    network_tool(input.process.binary)
    app_process(input.process.parent_name)
    v := {
        "severity": "HIGH",
        "msg": sprintf(
            "Network tool [%s] spawned by [%s] in pod [%s/%s] — possible exfiltration",
            [input.process.binary, input.process.parent_name,
             input.container.namespace, input.container.pod_name]
        ),
    }
}

network_tool(b) if b == "/usr/bin/curl"
network_tool(b) if b == "/usr/bin/wget"
network_tool(b) if b == "/bin/nc"

app_process(p) if p == "nginx"
app_process(p) if p == "node"
app_process(p) if p == "python3"

# Rule 3 — container escape attempt
violation[v] if {
    input.type == "process_exec"
    input.container.pod_name != ""
    escape_tool(input.process.binary)
    v := {
        "severity": "CRITICAL",
        "msg": sprintf(
            "CONTAINER ESCAPE — [%s] in pod [%s/%s]",
            [input.process.binary,
             input.container.namespace, input.container.pod_name]
        ),
    }
}

escape_tool(b) if b == "/usr/bin/nsenter"
escape_tool(b) if b == "/usr/bin/unshare"
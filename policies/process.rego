package agent.process

import future.keywords.if

# Rule 1 — shell spawned inside a container
deny[msg] {
    input.type == "process_exec"
    shell_binary(input.process.binary)
    msg := sprintf(
        "Shell spawned in pod [%s/%s] — binary: %s parent: %s",
        [input.container.namespace, input.container.pod_name,
         input.process.binary, input.process.parent_name]
    )
}

shell_binary(b) if b == "/bin/bash"
shell_binary(b) if b == "/bin/sh"
shell_binary(b) if b == "/usr/bin/bash"
shell_binary(b) if b == "/usr/bin/sh"

# Rule 2 — network tool spawned by app process
deny[msg] {
    input.type == "process_exec"
    network_tool(input.process.binary)
    app_process(input.process.parent_name)
    msg := sprintf(
        "Network tool [%s] spawned by [%s] in pod [%s/%s] — possible exfiltration",
        [input.process.binary, input.process.parent_name,
         input.container.namespace, input.container.pod_name]
    )
}

network_tool(b) if b == "/usr/bin/curl"
network_tool(b) if b == "/usr/bin/wget"
network_tool(b) if b == "/bin/nc"

app_process(p) if p == "nginx"
app_process(p) if p == "node"
app_process(p) if p == "python3"

# Rule 3 — container escape attempt
deny[msg] {
    input.type == "process_exec"
    escape_tool(input.process.binary)
    msg := sprintf(
        "CONTAINER ESCAPE — [%s] in pod [%s/%s]",
        [input.process.binary,
         input.container.namespace, input.container.pod_name]
    )
}

escape_tool(b) if b == "/usr/bin/nsenter"
escape_tool(b) if b == "/usr/bin/unshare"
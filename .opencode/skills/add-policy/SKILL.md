# Skill: Add Tenant Policy

## Purpose
Create a new YAML policy file for a tenant, defining tool access control for their agents.

## Workflow

1. **Gather requirements**:
   - Tenant name/ID
   - Agent ID(s)
   - What tools should the agent have access to?
   - What should be explicitly denied?
   - Should command execution be allowed?
   - Should file writes be allowed?
   - Any argument-level restrictions?

2. **Create policy file**: `config/policies/<tenant-id>.yaml`

3. **Policy structure**:
   ```yaml
   tenant: <tenant-id>
   
   agents:
     - id: <agent-id>
       sandbox_level: strict|standard|minimal
       allowed_tools: []          # Empty = all allowed (use denied_tools to restrict)
       denied_tools: []           # Explicit deny list
       allow_command_execution: false
       allow_file_write: false
       allow_network_access: true
       max_tool_calls: 20
       tool_policies:
         - name: <tool_name>
           max_calls: 10
           denied_arguments:
             <arg>: ["<blocked_substring>"]
           argument_patterns:
             <arg>: "<regex_allowlist>"
   ```

4. **Sandbox levels**:
   - `minimal` — Very few restrictions, for trusted internal agents
   - `standard` — Balanced: blocks dangerous tools by default, allows most reads
   - `strict` — Allowlist-only: only explicitly listed tools can be used

5. **Test the policy**: Start the server and send a request with the tenant/agent headers:
   ```bash
   curl http://localhost:8080/v1/tool/validate \
     -H "Authorization: Bearer <token>" \
     -H "X-Tenant-ID: <tenant-id>" \
     -H "X-Agent-ID: <agent-id>" \
     -d '{"name": "run_command", "arguments": {"command": "ls"}}'
   ```

6. **Reload without restart**: `curl -X POST http://localhost:8080/admin/policies/reload`

## Common Policy Templates

### Read-only chatbot (strict)
```yaml
agents:
  - id: chatbot
    sandbox_level: strict
    allowed_tools: [web_search, read_knowledge_base]
    denied_tools: [run_command, write_file, delete_file, read_file]
    allow_command_execution: false
    allow_file_write: false
    max_tool_calls: 5
```

### Code assistant (standard)
```yaml
agents:
  - id: code-assistant
    sandbox_level: standard
    allowed_tools: [read_file, write_file, run_command, web_search]
    denied_tools: [delete_file]
    allow_command_execution: true
    allow_file_write: true
    max_tool_calls: 30
    tool_policies:
      - name: run_command
        denied_arguments:
          command: ["|bash", "| sh", "rm -rf", "/dev/tcp/", "nc -e"]
      - name: read_file
        denied_arguments:
          filepath: [".env", "/etc/shadow", ".ssh/", ".aws/credentials"]
```

### Data analyst (standard, no execution)
```yaml
agents:
  - id: analyst
    sandbox_level: standard
    allowed_tools: [query_database, web_search, read_file]
    denied_tools: [run_command, write_file, delete_file]
    allow_command_execution: false
    allow_file_write: false
    max_tool_calls: 15
    tool_policies:
      - name: query_database
        denied_arguments:
          query: ["DROP", "DELETE", "TRUNCATE", "ALTER", "INSERT", "UPDATE"]
```

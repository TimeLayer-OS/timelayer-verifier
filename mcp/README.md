# tl-verify — MCP server

Let any MCP-capable agent (Claude, Cursor, custom) verify TimeLayer receipts and
run the TL-Agent gate — without leaving the chat. A thin, stdlib-only, stdio
JSON-RPC wrapper over the official binaries. No new trust surface: it shells out
to the same tools you can run by hand and reports their machine-readable result.
Fail-closed — anything that is not `VALID FINAL` / `ALLOW` comes back as an error.

## Tools
- **verify**(`cert_path`, `bundle_path`, `expect?`) → `timelayer-verifier verify … --json`
- **gate_check**(`bundle_dir`, `action_id`) → `tl-agent check …` (requires `tl-agent`)

## Install (one command)
```bash
# point it at the binaries, then register with your MCP client
export TL_VERIFIER=/path/to/timelayer-verifier      # required
export TL_AGENT=/path/to/tl-agent                   # optional (gate_check)
python3 tl_verify_mcp.py                             # speaks MCP stdio JSON-RPC
```

Example MCP client config (Claude Desktop / any stdio client):
```json
{
  "mcpServers": {
    "tl-verify": {
      "command": "python3",
      "args": ["/path/to/timelayer-verifier/mcp/tl_verify_mcp.py"],
      "env": { "TL_VERIFIER": "/path/to/timelayer-verifier" }
    }
  }
}
```

## Verify it works (no client needed)
```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | TL_VERIFIER=./target/release/timelayer-verifier python3 mcp/tl_verify_mcp.py
```

Stdlib only, Python 3.8+. Transport: newline-delimited JSON-RPC 2.0 over stdio
(MCP stdio), protocol `2024-11-05`.

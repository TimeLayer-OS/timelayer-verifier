#!/usr/bin/env python3
"""tl-verify — an MCP server that lets any agent verify TimeLayer receipts.

Distribution channel, not a new capability: it is a thin, stdio JSON-RPC wrapper
over the official binaries. Two tools:

  verify(cert_path, bundle_path, expect?)   -> timelayer-verifier verify … --json
  gate_check(bundle_dir, action_id)         -> tl-agent check … (if tl-agent is present)

No new trust surface: the server shells out to the same binaries you can run by
hand, and reports their machine-readable result. Fail-closed: anything that is
not VALID FINAL / ALLOW is returned as an error result.

Config (env):
  TL_VERIFIER   path to timelayer-verifier (else looked up on PATH)
  TL_AGENT      path to tl-agent            (else looked up on PATH; gate_check optional)

Transport: newline-delimited JSON-RPC 2.0 over stdin/stdout (MCP stdio).
Stdlib only — no dependencies.
"""
import json
import os
import shutil
import subprocess
import sys

VERSION = "0.1.0"
PROTOCOL = "2024-11-05"


def _bin(env, name):
    return os.environ.get(env) or shutil.which(name)


def _run(argv, timeout=30):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"not found: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


TOOLS = [
    {
        "name": "verify",
        "description": "Verify a TimeLayer receipt offline (VALID FINAL / NOT VALID / "
                       "UNVERIFIABLE). Optionally bind it to a specific action via `expect` "
                       "(sha256 hex) — a valid but unrelated receipt is refused.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cert_path": {"type": "string", "description": "path to cert.tlcert"},
                "bundle_path": {"type": "string", "description": "path to bundle.tlbundle"},
                "expect": {"type": "string", "description": "optional sha256 hex of the exact action/document"},
            },
            "required": ["cert_path", "bundle_path"],
        },
    },
    {
        "name": "gate_check",
        "description": "Run the TL-Agent pre-execution gate on one action in a bundle "
                       "(ALLOW / STOP<reason>). Requires the tl-agent binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bundle_dir": {"type": "string", "description": "path to the agent bundle directory"},
                "action_id": {"type": "string", "description": "the action id to gate-check"},
            },
            "required": ["bundle_dir", "action_id"],
        },
    },
]


def tool_verify(args):
    vbin = _bin("TL_VERIFIER", "timelayer-verifier")
    if not vbin:
        return True, "timelayer-verifier not found (set TL_VERIFIER or put it on PATH)"
    argv = [vbin, "verify", args["cert_path"], args["bundle_path"]]
    if args.get("expect"):
        argv += ["--expect", args["expect"]]
    argv += ["--json"]
    rc, out, err = _run(argv)
    text = out or err or "(no output)"
    is_error = rc != 0
    return is_error, text


def tool_gate_check(args):
    abin = _bin("TL_AGENT", "tl-agent")
    if not abin:
        return True, "tl-agent not found (set TL_AGENT or put it on PATH); gate_check is optional"
    argv = [abin, "check", args["bundle_dir"], args["action_id"]]
    vbin = _bin("TL_VERIFIER", "timelayer-verifier")
    if vbin:
        argv += ["--verifier", vbin]  # tl-agent needs the verifier to check the receipt
    rc, out, err = _run(argv)
    text = out or err or "(no output)"
    return rc != 0, text


DISPATCH = {"verify": tool_verify, "gate_check": tool_gate_check}


def handle(msg):
    """Return a response dict, or None for notifications (no reply)."""
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "tl-verify", "version": VERSION},
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        fn = DISPATCH.get(name)
        if not fn:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": f"unknown tool: {name}"}}
        try:
            is_error, text = fn(args)
        except KeyError as e:
            is_error, text = True, f"missing argument: {e}"
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }}
    if method is not None and mid is None:
        return None  # a notification (e.g. notifications/initialized) — no reply
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": f"method not found: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

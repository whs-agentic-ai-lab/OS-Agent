#!/usr/bin/env python3
"""Minimal non-root target service shared by C1, C2, and C3."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path not in {"/", "/health"}:
            self.send_error(404)
            return
        body = json.dumps(
            {
                "status": "ok",
                "target_id": os.environ.get("OS_AGENT_TARGET_ID", "unknown"),
                "topology_revision": os.environ.get(
                    "OS_AGENT_TOPOLOGY_REVISION", "unknown"
                ),
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        print(f"target-service: {message % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), TargetHandler).serve_forever()

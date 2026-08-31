"""Regression wire check for indexed audit arguments and JSONB-safe object keys.

Uses an explicitly supplied local Vector binary, loopback HTTP and a memory
repository. It never contacts Supabase or executes an audited command.
"""
import copy
import gzip
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from fastapi import FastAPI, Request
import pytest
import uvicorn
import yaml

from app.config import Settings
from app.evidence import create_evidence_router
from app.evidence_security import validate_json_value
from test_evidence_vector import ENVIRONMENT, TOKEN, _test_config


@pytest.mark.skipif(not os.getenv("VECTOR_BIN"), reason="VECTOR_BIN is absent; real Vector wire check not run")
def test_real_vector_indexed_audit_and_nul_keys_are_safe_for_api_batches(tmp_path):
    binary = Path(os.environ["VECTOR_BIN"]).resolve()
    assert binary.is_file()
    rows, wire = {}, []
    lock = threading.Lock()

    class Repository:
        def save_events(self, events):
            with lock:
                for event in events:
                    rows.setdefault((event.environment_id, event.event_id), event.model_dump(mode="json"))

    application = FastAPI()
    application.include_router(create_evidence_router(Settings(
        openrouter_api_key=None, openrouter_model="local-test", allowed_origins=(),
        runtime_dir=tmp_path, evidence_collector_token=TOKEN,
    ), Repository()))

    @application.middleware("http")
    async def observe(request: Request, call_next):
        body = await request.body()
        response = await call_next(request)
        if request.method == "POST":
            assert request.headers.get("content-encoding") == "gzip"
            wire.append({"status": response.status_code,
                         "events": [json.loads(line) for line in gzip.decompress(body).splitlines()]})
        return response

    secret = "synthetic-nul-key-secret"
    secrets = [secret, "synthetic-escaped-nul-key-secret", "synthetic-double-escaped-nul-key-secret",
               "structured-indexed-argument-secret", "escaped-double-quote-secret",
               "escaped-single-quote-secret", "truncated-quote-secret", "synthetic-x00-key-secret",
               "record-type-indexed-argument-secret"]
    payload = {"nested": {"bad\x00key": "nul-value", "bad\\u0000key": "literal-value"},
               "array": [{"nested\x00key": "array-value"}], "pa\x00ssword": secret,
               "to\\u0000ken": secrets[1], "pass\\\\u0000word": secrets[2], "pass\\x00word": secrets[7],
               "structured_audit": {"type": "EXECVE", "argc": 3, "uid": 1000,
                                    "a2_len": 8192, "a2[107]": secrets[3]},
               "structured_record_alias": {"record_type": "EXECVE", "a1_len": 64,
                                           "a1[0]": secrets[8]}}
    producer_ids = {"wire-edge-normal", "wire-edge-nul"}
    lines = []
    for event_id, content in (("wire-edge-normal", {"normal": "safe"}), ("wire-edge-nul", payload)):
        producer = {"evidence_kind": "executor", "event_id": event_id,
                    "event_type": "SYNTHETIC_TEST", "occurred_at": "2026-08-30T00:00:00Z",
                    "run_id": "wire-edge-run", "action_id": "wire-edge-action", "payload": content}
        lines.append(json.dumps({"event_id": "relay-" + event_id, "container_name": "os-agent-runtime",
                                 "container_id": "synthetic-container", "stream": "stdout",
                                 "source": "docker-logs-relay", "message": json.dumps(producer)}))
    fragments = ("766563746f722d6669787475", "72652d6f6e6c792d696e64657865642d617267756d656e74")
    audit_line = ('type=EXECVE msg=audit(1788048000.123:42): argc=3 a0="curl" a1="--token" '
                  f'a2_len=36 a2[0]={fragments[0]} a2[1]={fragments[1]}')
    syscall_line = "type=SYSCALL msg=audit(1788048000.123:45): syscall=59 a0=7ffd1234 a1=0 a2=3 uid=1000"
    audit_lines = [
        audit_line,
        r'type=EXECVE msg=audit(1788048000.123:43): argc=2 a0="escaped \" escaped-double-quote-secret" '
        r"a1[107]='escaped \' escaped-single-quote-secret' uid=1000",
        'type=EXECVE msg=audit(1788048000.123:44): argc=3 a2_len=8192 a2[107]="truncated-quote-secret ' + "\\",
        syscall_line,
    ]
    expected_events = len(lines) + len(audit_lines)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    uri = f"http://127.0.0.1:{listener.getsockname()[1]}/internal/evidence/events"
    server = uvicorn.Server(uvicorn.Config(application, log_level="error", access_log=False,
                                         lifespan="off", loop="asyncio", ws="none"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    process = None
    try:
        thread.start()
        deadline = time.monotonic() + 3
        while not server.started and time.monotonic() < deadline:
            threading.Event().wait(0.02)
        assert server.started
        config_path, local_output, _ = _test_config(tmp_path, uri, lines)
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        source = Path(__file__).resolve().parents[2] / "infra/terraform/config/vector/vector.yaml.tpl"
        template = source.read_text(encoding="utf-8").replace("%{ if remote_sink_enabled ~}", "").replace("%{ endif ~}", "")
        production = yaml.safe_load(template)
        audit_file = tmp_path / "synthetic-audit.log"
        audit_file.write_text("\n".join(audit_lines) + "\n", encoding="utf-8", newline="\n")
        # Preserve the production audit source options and channel transform.
        config["sources"]["auditd"] = copy.deepcopy(production["sources"]["auditd"])
        config["sources"]["auditd"]["include"] = [audit_file.as_posix()]
        config["transforms"]["tag_audit"] = production["transforms"]["tag_audit"]
        config["transforms"]["normalize"]["inputs"].append("tag_audit")
        config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        log = tmp_path / "vector-edge.log"
        with log.open("wb") as output:
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}}
            environment["NO_PROXY"] = "127.0.0.1,localhost"
            process = subprocess.Popen([str(binary), "--config", str(config_path), "--quiet"],
                stdout=output, stderr=subprocess.STDOUT, env=environment,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            deadline = time.monotonic() + 15
            while process.poll() is None and time.monotonic() < deadline:
                with lock:
                    complete = len(rows) == expected_events
                if complete and local_output.exists() and len(local_output.read_text(encoding="utf-8").splitlines()) == expected_events:
                    break
                threading.Event().wait(0.05)
            with log.open("rb") as diagnostic:
                detail = diagnostic.read(8192).decode("utf-8", errors="replace")
            assert process.poll() is None, detail
            with lock:
                actual = dict(rows)
            assert len(actual) == expected_events, detail
            assert wire and all(batch["status"] == 200 for batch in wire), [batch["status"] for batch in wire]
            assert any(producer_ids.issubset({event["event_id"] for event in batch["events"]}) for batch in wire)
            edge = actual[(ENVIRONMENT, "wire-edge-nul")]["payload"]["payload"]
            assert len(edge["nested"]) == 2 and set(edge["nested"].values()) == {"nul-value", "literal-value"}
            assert list(edge["array"][0].values()) == ["array-value"]
            assert edge["structured_audit"] == {"type": "EXECVE", "argc": 3, "uid": 1000,
                                                "a2_len": 8192, "a2[107]": "[REDACTED]"}
            assert edge["structured_record_alias"] == {"record_type": "EXECVE", "a1_len": 64,
                                                        "a1[0]": "[REDACTED]"}
            audit = next(event for event in actual.values() if "a2_len=36" in event["message"])
            assert audit["payload"]["audit_arguments_omitted"] is True
            syscall = next(event for event in actual.values() if event["event_type"] == "audit.syscall")
            assert syscall["message"] == syscall_line
            assert syscall["payload"]["message"] == syscall_line
            assert "audit_arguments_omitted" not in syscall["payload"]
            local_rows = [json.loads(line) for line in local_output.read_text(encoding="utf-8").splitlines()]
            rendered = json.dumps([local_rows, list(actual.values()), wire])
            assert all(value not in rendered for value in secrets)
            assert all(fragment not in rendered for fragment in fragments)
            # Check Vector's local sink as well as the API result: backend
            # masking must not hide invalid NULs or a collector-side leak.
            for event in [*local_rows, *actual.values()]:
                validate_json_value(event, reject_nul=True)
            assert audit["status"] == "ok"
            assert actual[(ENVIRONMENT, "wire-edge-normal")]["status"] == "ok"
            # Repairing a NUL remains visible under the existing collection-error
            # contract; it must not reject the repaired event or its valid peer.
            repaired = actual[(ENVIRONMENT, "wire-edge-nul")]
            assert repaired["status"] == "collection_error"
            assert repaired["payload"]["nul_byte_escaped"] is True
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        server.should_exit = True
        if thread.is_alive():
            thread.join(timeout=3)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=1)
        listener.close()

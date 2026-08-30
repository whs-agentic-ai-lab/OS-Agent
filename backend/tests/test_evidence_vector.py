"""Opt-in local wire check; NOT a remote/Supabase E2E test.

Set VECTOR_BIN to an existing Vector executable. No executable, dependency,
remote service, database, or snapshot is installed/created by this test.
Real: emitter, Vector transforms/sinks, HTTP/gzip/retry, FastAPI validation.
Double: an in-memory repository with the DB's (environment_id, event_id) key.
"""

from contextlib import redirect_stdout
import gzip
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from fastapi import FastAPI, Request
import httpx
import pytest
import uvicorn
import yaml

from app.config import Settings
from app.evidence import EVENT_REQUEST_LIMIT, EvidenceEvent, create_evidence_router
from app.evidence_emitter import emit_execution_evidence
from app.schemas import RuntimeAgentResult
from app.verifiers import VerificationResult


TOKEN = "local-vector-wire-test-only"
ENVIRONMENT = "e2e-vector-local-only"
SECRET = "local-wire-secret-must-be-masked"


class StrictRepositoryDouble:
    """Fail one real HTTP request, then mimic only DB uniqueness, not Supabase."""

    def __init__(self):
        self.rows: dict[tuple[str, str], dict] = {}
        self.attempts: list[list[dict]] = []
        self.lock = threading.Lock()

    def save_events(self, events: list[EvidenceEvent]) -> None:
        assert all(isinstance(event, EvidenceEvent) for event in events)
        with self.lock:
            serialized = [event.model_dump(mode="json") for event in events]
            self.attempts.append(serialized)
            if len(self.attempts) == 1:
                raise RuntimeError("Intentional local persistence outage")
            for event in serialized:
                self.rows.setdefault((event["environment_id"], event["event_id"]), event)


def _fixtures() -> tuple[list[str], list[dict]]:
    # This is fixture data; neither a tool nor a verifier is executed.
    result = RuntimeAgentResult(
        run_id="e2e-vector-run", action_id="e2e-vector-action",
        subject_mode="host", executor_mode="host",
        trust_boundary_id="TB-HH-U1U2", source_environment="u1", target_environment="u2",
        source="u1", target="u2", applied_profile="wire-fixture", applied_profile_state={},
        runtime_agent="local-wire-fixture", planner_mode="local",
        tool="file.content", action="read", resource_ref="target-canary",
        runtime_result="denied", outcome="OS_DENIED", attempted=True,
        output="Authorization: Bearer " + SECRET, exit_code=13,
    )
    captured = io.StringIO()
    with redirect_stdout(captured):
        emit_execution_evidence("TOOL_RESULT", result=result)
        emit_execution_evidence(
            "VERIFIER_RESULT", result=result,
            verification=VerificationResult("PASS", "fixture_verifier", {"expected_denial": True}),
        )
    producer = [json.loads(line) for line in captured.getvalue().splitlines()]
    wrapped = [json.dumps({
        "event_id": f"e2e-relay-{index}",
        "occurred_at": "2026-08-30T00:00:00Z", "source": "docker-logs-relay",
        "container_id": "e2e-container", "container_name": "os-agent-runtime",
        "stream": "stdout", "message": json.dumps(event, ensure_ascii=False),
    }, ensure_ascii=False) for index, event in enumerate(producer)]
    return [
        *wrapped, wrapped[1],  # same producer ID delivered twice by Vector
        '{"password":"' + SECRET + '"',  # malformed JSON must remain a parse_error
        json.dumps({
            "event_id": "e2e-foreign-container", "source": "docker-logs-relay",
            "container_name": "os-agent-container2", "run_id": "must-not-be-correlated",
            "message": "api_key=" + SECRET, "nested": {"password": SECRET},
        }),
    ], producer


def _test_config(tmp_path: Path, uri: str, lines: list[str]) -> tuple[Path, Path, Path]:
    root = Path(__file__).resolve().parents[2]
    vector_root = root / "infra/terraform/config/vector"
    substitutions = {
        "${environment_id}": ENVIRONMENT,
        "${topology_revision}": "local-wire-fixture-v1",
        "${evidence_api_uri}": uri,
    }

    def render(source: str) -> str:
        source = source.replace("%{ if remote_sink_enabled ~}", "").replace("%{ endif ~}", "")
        for name, value in substitutions.items():
            source = source.replace(name, value)
        return source

    config = yaml.safe_load(render((vector_root / "vector.yaml.tpl").read_text(encoding="utf-8")))
    normalizer = tmp_path / "normalize.vrl"
    normalizer.write_text(render((vector_root / "normalize.vrl.tpl").read_text(encoding="utf-8")), encoding="utf-8")
    fixture = tmp_path / "docker-fixture.ndjson"
    fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")
    collected = tmp_path / "collected.ndjson"
    data_dir, secret_dir = tmp_path / "vector-data", tmp_path / "secrets"
    data_dir.mkdir()
    secret_dir.mkdir()
    (secret_dir / "collector_token").write_text(TOKEN + "\n", encoding="utf-8")

    # Only replace unavailable Linux sources, fixture/output/secret paths and
    # the URI (loopback HTTP, never a remote TLS exemption). Preserve the real
    # source options, transforms, batch, buffers, headers, gzip, retry and ack.
    source = config["sources"]["docker_logs"]
    source["include"] = [fixture.as_posix()]
    config["sources"] = {"docker_logs": source}
    config["transforms"] = {key: config["transforms"][key] for key in (
        "tag_docker_logs", "normalize", "normalization_error",
    )}
    config["transforms"]["normalize"]["inputs"] = ["tag_docker_logs"]
    config["transforms"]["normalize"]["file"] = normalizer.as_posix()
    config["data_dir"] = data_dir.as_posix()
    config["secret"]["collector"]["path"] = secret_dir.as_posix()
    config["sinks"]["local_evidence"]["path"] = collected.as_posix()
    config_path = tmp_path / "vector.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return config_path, collected, fixture


@pytest.mark.skipif(not os.getenv("VECTOR_BIN"), reason="VECTOR_BIN is absent; real local Vector wire test not run")
def test_real_vector_retry_auth_ndjson_context_masking_and_duplicate_boundary(tmp_path):
    binary = Path(os.environ["VECTOR_BIN"]).resolve()
    assert binary.is_file(), "VECTOR_BIN must name an existing executable; this test never installs it"
    repository = StrictRepositoryDouble()
    application = FastAPI()
    application.include_router(create_evidence_router(Settings(
        openrouter_api_key=None, openrouter_model="local-test", allowed_origins=(),
        runtime_dir=tmp_path, evidence_collector_token=TOKEN,
    ), repository))
    wire: list[dict] = []

    @application.middleware("http")
    async def observe_actual_wire(request: Request, call_next):
        body = await request.body()
        response = await call_next(request)
        if request.method == "POST":
            wire.append({
                "authorization": request.headers.get("authorization"),
                "encoding": request.headers.get("content-encoding"),
                "content_type": request.headers.get("content-type"),
                "body": body, "status": response.status_code,
            })
        return response

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    uri = f"http://127.0.0.1:{listener.getsockname()[1]}/internal/evidence/events"
    server = uvicorn.Server(uvicorn.Config(
        application, log_level="error", access_log=False, lifespan="off", loop="asyncio", ws="none",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    process = None
    vector_log = tmp_path / "vector-process.log"
    try:
        thread.start()
        started_deadline = time.monotonic() + 3
        while not server.started and time.monotonic() < started_deadline:
            threading.Event().wait(0.02)
        assert server.started, "Temporary loopback API did not start"
        with httpx.Client(timeout=2, trust_env=False) as client:
            assert client.head(uri, headers={"Authorization": "Bearer " + TOKEN}).status_code == 200
            bad_auth = client.post(uri, content=b"{}\n", headers={
                "Authorization": "Bearer wrong-local-test-token", "Content-Type": "application/x-ndjson",
            })
            assert bad_auth.status_code == 401
            bad_input = client.post(uri, content=b"{}\n", headers={
                "Authorization": "Bearer " + TOKEN, "Content-Type": "application/x-ndjson",
            })
            assert bad_input.status_code == 422
            assert not repository.attempts

        lines, producer = _fixtures()
        config, local_output, fixture = _test_config(tmp_path, uri, lines)
        with vector_log.open("wb") as output:
            process = subprocess.Popen(
                [str(binary), "--config", str(config), "--quiet"],
                stdout=output, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                env={
                    **{key: value for key, value in os.environ.items() if key.upper() not in (
                        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                    )},
                    "NO_PROXY": "127.0.0.1,localhost",
                },
            )
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline and process.poll() is None:
                gzip_requests = [item for item in wire if item["encoding"] == "gzip"]
                with repository.lock:
                    ready = len(repository.rows) == 4
                if ready and gzip_requests and gzip_requests[-1]["status"] == 200 and local_output.exists():
                    if len(local_output.read_text(encoding="utf-8").splitlines()) == 5:
                        break
                threading.Event().wait(0.05)
            # Never dump unlimited process output or a real credential to pytest.
            with vector_log.open("rb") as diagnostic_file:
                diagnostics = diagnostic_file.read(8192).decode("utf-8", errors="replace")
            assert process.poll() is None, diagnostics
            assert SECRET not in diagnostics
            with repository.lock:
                rows, attempts = dict(repository.rows), list(repository.attempts)
            gzip_requests = [item for item in wire if item["encoding"] == "gzip"]
            assert len(rows) == 4, diagnostics
            assert len(attempts) >= 2, "Vector did not retry the API's 503"
            assert attempts[0] == attempts[1], "The retried batch changed"
            assert gzip_requests[0]["status"] == 503
            assert gzip_requests[-1]["status"] == 200
            assert all(item["authorization"] == "Bearer " + TOKEN for item in gzip_requests)
            assert all(item["content_type"] == "application/x-ndjson" for item in gzip_requests)
            for item in gzip_requests:
                ndjson = gzip.decompress(item["body"])
                # HTTP framing separates records with newlines but Vector
                # does not append a final newline to the batch.
                assert len(ndjson.splitlines()) == 5
                assert SECRET.encode() not in ndjson
                for line in ndjson.splitlines():
                    EvidenceEvent.model_validate_json(line)

            local_rows = [json.loads(line) for line in local_output.read_text(encoding="utf-8").splitlines()]
            assert len(local_rows) == 5  # local delivery preserves the duplicate
            assert SECRET not in json.dumps(local_rows)
            assert SECRET not in json.dumps(list(rows.values()))
            assert {row["event_id"] for row in local_rows} == {key[1] for key in rows}
            for event in producer:
                stored = rows[(ENVIRONMENT, event["event_id"])]
                assert stored["source_type"] == "executor"
                assert stored["context"] == {
                    "run_id": "e2e-vector-run", "action_id": "e2e-vector-action",
                    "step_id": None, "tool_call_id": None,
                }
                if event["event_type"] == "VERIFIER_RESULT":
                    assert stored["payload"]["payload"] == event["payload"]
                else:
                    # Raw output can undergo additional conservative masking
                    # in Vector; execution outcomes/IDs must remain exact.
                    actual_result = dict(stored["payload"]["payload"]["tool_result"])
                    expected_result = dict(event["payload"]["tool_result"])
                    assert "[REDACTED]" in actual_result.pop("output")
                    expected_result.pop("output")
                    assert actual_result == expected_result
            assert rows[(ENVIRONMENT, producer[0]["event_id"])]["payload"]["payload"]["tool_result"]["outcome"] == "OS_DENIED"
            assert rows[(ENVIRONMENT, producer[1]["event_id"])]["payload"]["payload"]["verifier_result"]["status"] == "PASS"
            unparsed = next(row for row in rows.values() if row["status"] == "parse_error")
            assert unparsed["event_type"] == "evidence.parse_error"
            foreign = rows[(ENVIRONMENT, "e2e-foreign-container")]
            assert foreign["source_type"] == "docker_log"
            assert foreign["context"] == dict.fromkeys(["run_id", "action_id", "step_id", "tool_call_id"])

            # A second successful HTTP request also replays an already stored
            # event through Vector's real file source and existing HTTP sink.
            with fixture.open("a", encoding="utf-8") as fixture_file:
                fixture_file.write(lines[1] + "\n")
            replay_deadline = time.monotonic() + 4
            successes = []
            while time.monotonic() < replay_deadline and process.poll() is None:
                successes = [item for item in wire if item["encoding"] == "gzip" and item["status"] == 200]
                if len(successes) >= 2 and len(local_output.read_text(encoding="utf-8").splitlines()) == 6:
                    break
                threading.Event().wait(0.05)
            assert len(successes) == 2, "The successful batch was not replayed through Vector"
            replayed = [json.loads(line) for line in gzip.decompress(successes[-1]["body"]).splitlines()]
            assert [event["event_id"] for event in replayed] == [producer[1]["event_id"]]
            with repository.lock:
                assert len(repository.rows) == 4
                assert len(repository.attempts) == 3
            assert len(local_output.read_text(encoding="utf-8").splitlines()) == 6
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


@pytest.mark.skipif(not os.getenv("VECTOR_BIN"), reason="VECTOR_BIN is absent; real local Vector wire test not run")
def test_real_vector_escape_heavy_source_batches_fit_api_limit(tmp_path):
    """HTTP max_bytes precedes JSON escaping; ordinary file events must not get 413."""
    binary = Path(os.environ["VECTOR_BIN"]).resolve()
    assert binary.is_file(), "VECTOR_BIN must name an existing executable; this test never installs it"
    rows = {}
    lock = threading.Lock()

    class Repository:
        def save_events(self, events: list[EvidenceEvent]) -> None:
            with lock:
                for event in events:
                    rows.setdefault((event.environment_id, event.event_id), event.model_dump(mode="json"))

    application = FastAPI()
    application.include_router(create_evidence_router(Settings(
        openrouter_api_key=None, openrouter_model="local-test", allowed_origins=(),
        runtime_dir=tmp_path, evidence_collector_token=TOKEN,
    ), Repository()))
    wire = []

    @application.middleware("http")
    async def observe_batch_size(request: Request, call_next):
        body = await request.body()
        response = await call_next(request)
        if request.method == "POST":
            expanded = gzip.decompress(body)
            wire.append({
                "expanded_bytes": len(expanded), "events": len(expanded.splitlines()),
                "status": response.status_code,
            })
        return response

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    uri = f"http://127.0.0.1:{listener.getsockname()[1]}/internal/evidence/events"
    server = uvicorn.Server(uvicorn.Config(
        application, log_level="error", access_log=False, lifespan="off", loop="asyncio", ws="none",
    ))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    process = None
    vector_log = tmp_path / "vector-process.log"
    # Each input is ~240 KiB (within the existing 256 KiB source cap), but
    # message + payload JSON escaping expands a former 4 MiB batch beyond 8 MiB.
    message = "\x01" * 40000
    event_ids = {f"e2e-batch-size-{index}" for index in range(26)}
    lines = [json.dumps({
        "event_id": event_id, "source": "docker-logs-relay",
        "container_name": "os-agent-container1", "stream": "stdout",
        "occurred_at": "2026-08-30T00:00:00Z", "message": message,
    }) for event_id in sorted(event_ids)]
    try:
        thread.start()
        started_deadline = time.monotonic() + 3
        while not server.started and time.monotonic() < started_deadline:
            threading.Event().wait(0.02)
        assert server.started, "Temporary loopback API did not start"
        config, local_output, _fixture = _test_config(tmp_path, uri, lines)
        rendered = yaml.safe_load(config.read_text(encoding="utf-8"))
        assert max(len(line.encode()) for line in lines) < rendered["sources"]["docker_logs"]["max_line_bytes"]
        assert rendered["sinks"]["evidence_api"]["batch"]["max_bytes"] <= 1048576
        with vector_log.open("wb") as output:
            process = subprocess.Popen(
                [str(binary), "--config", str(config), "--quiet"],
                stdout=output, stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                env={
                    **{key: value for key, value in os.environ.items() if key.upper() not in (
                        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                    )}, "NO_PROXY": "127.0.0.1,localhost",
                },
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None:
                with lock:
                    ready = len(rows) == len(event_ids)
                if ready and sum(item["events"] for item in wire) == len(event_ids) and local_output.exists():
                    if len(local_output.read_text(encoding="utf-8").splitlines()) == len(event_ids):
                        break
                threading.Event().wait(0.05)
            with vector_log.open("rb") as diagnostic_file:
                diagnostics = diagnostic_file.read(8192).decode("utf-8", errors="replace")
            assert process.poll() is None, diagnostics
            with lock:
                stored_rows = dict(rows)
            assert set(stored_rows) == {(ENVIRONMENT, event_id) for event_id in event_ids}, diagnostics
            assert len(wire) >= 3, "Escape-heavy events were not split into safe batches"
            assert all(item["status"] == 200 for item in wire), wire
            assert all(item["expanded_bytes"] <= EVENT_REQUEST_LIMIT for item in wire), wire
            assert max(item["expanded_bytes"] for item in wire) > 4 * 1024 * 1024
            assert "dropping the request" not in diagnostics
            assert "Events dropped" not in diagnostics
            for row in stored_rows.values():
                assert row["source_type"] == "docker_log"
                assert row["status"] == "ok"
                assert row["message"] == row["payload"]["message"] == message
            local_rows = [json.loads(line) for line in local_output.read_text(encoding="utf-8").splitlines()]
            assert {row["event_id"] for row in local_rows} == event_ids
            assert len(local_rows) == len(event_ids)
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

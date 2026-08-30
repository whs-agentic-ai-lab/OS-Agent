from __future__ import annotations

import hashlib
import json
from pathlib import Path
import urllib.error

import pytest

from host_runtime import evidence_upload as uploader


IDENTITY = ("test-evidence-run", "test-evidence-action", "before", "U1C1", "C1")


def _write_index(directory: Path) -> None:
    lines = [
        hashlib.sha256(path.read_bytes()).hexdigest() + "  ./" + path.name
        for path in sorted(directory.iterdir()) if path.name != "artifact-sha256.txt"
    ]
    (directory / "artifact-sha256.txt").write_text("\n".join(lines) + "\n", encoding="ascii")


@pytest.fixture
def capture(tmp_path, monkeypatch):
    monkeypatch.setattr(uploader, "ROOT", tmp_path / "runs")
    monkeypatch.setattr(uploader, "CONFIG_PATH", tmp_path / "upload.json")
    monkeypatch.setattr(uploader, "TOKEN_FILE", tmp_path / "collector_token")
    monkeypatch.setattr(uploader, "EVENT_FILE", tmp_path / "state-captures.ndjson")
    monkeypatch.setattr(uploader, "LOCK_FILE", tmp_path / "state-event.lock")
    uploader.CONFIG_PATH.write_text(json.dumps({
        "enabled": True, "api_url": "https://evidence.invalid", "environment_id": "test-evidence-env",
        "token_file": str(uploader.TOKEN_FILE),
    }), encoding="utf-8")
    uploader.TOKEN_FILE.write_text("test-collector-private-token", encoding="ascii")
    directory = uploader.ROOT / IDENTITY[0] / "actions" / IDENTITY[1] / IDENTITY[2]
    directory.mkdir(parents=True)
    filenames = uploader.COMMON_FILES | {"container_inspect.json", "container_processes.txt", "container_diff.txt"}
    for filename in filenames:
        (directory / filename).write_text("test capture\n", encoding="utf-8")
    manifest = dict(zip(("run_id", "action_id", "phase", "path_id", "target_id"), IDENTITY))
    manifest.update(schema_version="state-capture-v1", status="COMPLETE", occurred_at="2026-08-30T00:00:00Z")
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (directory / "container_inspect.json").write_text(json.dumps([
        {"Config": {"Image": "test-image"}, "Args": ["--token", "artifact-test-secret"]},
    ]), encoding="utf-8")
    (directory / "processes.txt").write_text("pid=1 password=artifact-test-secret\n", encoding="utf-8")
    _write_index(directory)
    return directory


class Response:
    status = 200

    def __init__(self, request):
        headers = {key.lower(): value for key, value in request.header_items()}
        filename = request.full_url.rsplit("/", 1)[1]
        self.payload = {
            "status": "uploaded", "filename": filename,
            "event_id": headers["x-evidence-event-id"],
            "bucket": "os-agent-evidence",
            "object_path": "test-evidence-env/" + headers["x-evidence-sha256"] + "/" + filename,
            "size_bytes": len(request.data),
            "sha256": hashlib.sha256(request.data).hexdigest(),
            "original_sha256": headers["x-evidence-original-sha256"],
        }

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, size):
        return json.dumps(self.payload).encode()[:size]


@pytest.fixture
def transport(monkeypatch):
    requests = []

    class Opener:
        def open(self, request, timeout):
            assert timeout == 30
            assert request.method == "PUT"
            requests.append(request)
            return Response(request)

    def build_opener(*handlers):
        assert any(isinstance(handler, uploader.NoRedirects) for handler in handlers)
        return Opener()

    monkeypatch.setattr(uploader.urllib.request, "build_opener", build_opener)
    return requests


def test_disabled_upload_does_not_read_capture_or_use_network(capture, transport, monkeypatch):
    uploader.CONFIG_PATH.write_text('{"enabled":false}', encoding="ascii")
    monkeypatch.setattr(uploader, "_capture", lambda context: pytest.fail("disabled upload read capture"))
    assert uploader.upload_capture(*IDENTITY) is None
    assert transport == []


def test_missing_configuration_defaults_to_disabled(capture, transport):
    uploader.CONFIG_PATH.unlink()
    assert uploader.upload_capture(*IDENTITY) is None
    assert transport == []


@pytest.mark.parametrize("identity", [
    ("../secret", *IDENTITY[1:]),
    (IDENTITY[0], "..", *IDENTITY[2:]),
    (IDENTITY[0], IDENTITY[1], "../../before", *IDENTITY[3:]),
    (*IDENTITY[:3], "U1C1", "U2"),
])
def test_identity_cannot_select_an_arbitrary_path(capture, transport, identity):
    with pytest.raises(uploader.UploadFailure, match="invalid_capture_identity"):
        uploader.upload_capture(*identity)
    assert transport == []


@pytest.mark.parametrize("api_url", [
    "http://evidence.invalid", "https://user:password@evidence.invalid",
    "https://evidence.invalid?token=secret", "https://evidence.invalid/#fragment",
])
def test_rejects_unsafe_api_configuration(capture, transport, api_url):
    config = json.loads(uploader.CONFIG_PATH.read_text())
    config["api_url"] = api_url
    uploader.CONFIG_PATH.write_text(json.dumps(config))
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["error_code"] == "invalid_upload_configuration"
    assert transport == []


def test_valid_upload_sanitizes_transmitted_copy_and_preserves_capture(capture, transport):
    originals = {path.name: path.read_bytes() for path in capture.iterdir()}
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["event_type"] == "ARTIFACT_UPLOADED"
    assert summary["status"] == "uploaded"
    assert summary["collection_error"] is False
    assert summary["expected_artifact_count"] == len(originals)
    assert summary["uploaded_artifact_count"] == len(originals)
    assert summary["capture_event_id"] == "state-" + hashlib.sha256(originals["artifact-sha256.txt"]).hexdigest()
    assert len(transport) == len(originals)
    for request in transport:
        headers = {key.lower(): value for key, value in request.header_items()}
        name = request.full_url.rsplit("/", 1)[1]
        assert headers["authorization"] == "Bearer test-collector-private-token"
        assert headers["x-evidence-environment-id"] == "test-evidence-env"
        assert headers["x-evidence-sha256"] == hashlib.sha256(request.data).hexdigest()
        assert headers["x-evidence-original-sha256"] == hashlib.sha256(originals[name]).hexdigest()
        assert b"artifact-test-secret" not in request.data
    assert {path.name: path.read_bytes() for path in capture.iterdir()} == originals
    assert "test-collector-private-token" not in json.dumps(summary)


def test_republish_uploads_existing_capture_without_changing_it(capture, transport):
    originals = {path.name: path.read_bytes() for path in capture.iterdir()}
    first = uploader.upload_capture(*IDENTITY)
    second = uploader.upload_capture(*IDENTITY)
    assert first["capture_event_id"] == second["capture_event_id"]
    assert first["event_id"] != second["event_id"]
    assert first["artifacts"] == second["artifacts"]
    assert len(transport) == 2 * len(originals)
    assert {path.name: path.read_bytes() for path in capture.iterdir()} == originals


def test_existing_after_capture_uploads_its_existing_diff(capture, transport):
    directory = capture.with_name("after")
    capture.rename(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    manifest["phase"] = "after"
    (directory / "manifest.json").write_text(json.dumps(manifest))
    (directory / "diff-from-before.txt").write_text("--- before\n+++ after\n")
    _write_index(directory)
    summary = uploader.upload_capture(IDENTITY[0], IDENTITY[1], "after", *IDENTITY[3:])
    assert summary["status"] == "uploaded"
    assert any(item["filename"] == "diff-from-before.txt" for item in summary["artifacts"])
    assert all("/after/" in request.full_url for request in transport)


def test_existing_host_capture_uses_only_host_files(capture, transport):
    for filename in ("container_inspect.json", "container_processes.txt", "container_diff.txt"):
        (capture / filename).unlink()
    for filename in ("identity.txt", "target_processes.txt"):
        (capture / filename).write_text("host capture\n")
    manifest = json.loads((capture / "manifest.json").read_text())
    manifest.update(path_id="U1U2", target_id="U2")
    (capture / "manifest.json").write_text(json.dumps(manifest))
    _write_index(capture)
    summary = uploader.upload_capture(*IDENTITY[:3], "U1U2", "U2")
    assert summary["status"] == "uploaded"
    filenames = {item["filename"] for item in summary["artifacts"]}
    assert {"identity.txt", "target_processes.txt"}.issubset(filenames)
    assert "container_inspect.json" not in filenames


def test_corrupt_file_fails_before_any_http(capture, transport):
    (capture / "processes.txt").write_text("changed after index")
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["event_type"] == "ARTIFACT_UPLOAD_FAILED"
    assert summary["error_code"] == "artifact_integrity_failed"
    assert summary["collection_error"] is True
    assert summary["capture_event_id"].startswith("state-")
    assert transport == []


@pytest.mark.parametrize("index", [
    "a" * 64 + "  ./../../collector_token\n",
    "a" * 64 + "  /etc/vector/secrets/collector_token\n",
    "a" * 64 + "  ./artifact-sha256.txt\n",
    "a" * 64 + "  ./processes.txt\n" + "a" * 64 + "  ./processes.txt\n",
])
def test_index_cannot_read_external_or_duplicate_paths(capture, transport, index):
    (capture / "artifact-sha256.txt").write_text(index, encoding="ascii")
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["error_code"] == "invalid_artifact_index"
    assert transport == []


@pytest.mark.parametrize("key,value", [("status", "FAILED"), ("run_id", "another-run"), ("target_id", "U2")])
def test_manifest_must_match_completed_capture_identity(capture, transport, key, value):
    manifest = json.loads((capture / "manifest.json").read_text())
    manifest[key] = value
    (capture / "manifest.json").write_text(json.dumps(manifest))
    _write_index(capture)
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["error_code"] == "artifact_manifest_mismatch"
    assert transport == []


def test_unknown_extra_file_is_not_uploaded(capture, transport):
    (capture / "unexpected.env").write_text("SUPABASE_SECRET_KEY=must-not-upload")
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["error_code"] == "invalid_artifact_index"
    assert transport == []


@pytest.mark.parametrize("directory_symlink", [False, True])
def test_rejects_symlink_file_or_component(capture, transport, tmp_path, directory_symlink):
    if directory_symlink:
        original = capture.parent
        destination = tmp_path / "external-action"
        original.rename(destination)
    else:
        original = capture / "processes.txt"
        destination = tmp_path / "external-processes.txt"
        original.rename(destination)
    try:
        original.symlink_to(destination, target_is_directory=directory_symlink)
    except OSError:
        pytest.skip("creating symlinks is not permitted on this Windows host")
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["error_code"] == "unsafe_artifact_path"
    assert transport == []


def test_file_size_cap_is_checked_before_upload(capture, transport):
    with (capture / "processes.txt").open("wb") as stream:
        stream.truncate(uploader.MAX_FILE_BYTES + 1)
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["error_code"] == "artifact_too_large"
    assert transport == []


def test_upload_failure_keeps_partial_references_and_no_sensitive_exception(capture, monkeypatch):
    calls = []

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            if len(calls) == 2:
                raise urllib.error.URLError("password=raw-secret Bearer test-collector-private-token")
            return Response(request)

    monkeypatch.setattr(uploader.urllib.request, "build_opener", lambda *args: Opener())
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["event_type"] == "ARTIFACT_UPLOAD_FAILED"
    assert summary["error_code"] == "artifact_http_failure"
    assert summary["uploaded_artifact_count"] == 1
    assert summary["expected_artifact_count"] > 1
    assert summary["capture_event_id"].startswith("state-")
    assert "raw-secret" not in json.dumps(summary)
    assert "test-collector-private-token" not in json.dumps(summary)


@pytest.mark.parametrize("field,value", [("sha256", "0" * 64), ("size_bytes", -1), ("status", "queued")])
def test_success_response_must_confirm_transmitted_hash_and_size(capture, monkeypatch, field, value):
    class Opener:
        def open(self, request, timeout):
            response = Response(request)
            response.payload[field] = value
            return response

    monkeypatch.setattr(uploader.urllib.request, "build_opener", lambda *args: Opener())
    summary = uploader.upload_capture(*IDENTITY)
    assert summary["status"] == "failed"
    assert summary["error_code"] == "invalid_upload_response"


def test_redirects_are_not_followed():
    assert uploader.NoRedirects().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid") is None


def test_cli_appends_summary_without_replacing_state_captured_event(capture, transport):
    original = '{"event_type":"STATE_CAPTURED","event_id":"existing-capture"}\n'
    uploader.EVENT_FILE.write_text(original, encoding="ascii")
    assert uploader.main(list(IDENTITY)) == 0
    lines = uploader.EVENT_FILE.read_text().splitlines()
    assert lines[0] + "\n" == original
    summary = json.loads(lines[1])
    assert summary["event_type"] == "ARTIFACT_UPLOADED"
    assert summary["run_id"] == IDENTITY[0]
    assert summary["action_id"] == IDENTITY[1]


def test_cli_logs_failed_upload_without_raising_or_printing_secret(capture, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError("password=raw-secret")

    monkeypatch.setattr(uploader, "_upload", fail)
    assert uploader.main(list(IDENTITY)) == 1
    summary = json.loads(uploader.EVENT_FILE.read_text())
    assert summary["event_type"] == "ARTIFACT_UPLOAD_FAILED"
    assert summary["collection_error"] is True
    assert "raw-secret" not in uploader.EVENT_FILE.read_text()
    assert capsys.readouterr() == ("", "")


def test_uploader_matches_real_fastapi_contract_without_remote_storage(capture, monkeypatch, tmp_path):
    """Local route/transport contract only: the storage repository is an in-memory fake."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.config import Settings
    from app.evidence import create_evidence_router

    stored = {}

    class Repository:
        def save_artifact(self, metadata, data):
            stored[metadata["filename"]] = (metadata, data)
            return metadata

    application = FastAPI()
    application.include_router(create_evidence_router(Settings(
        openrouter_api_key=None, openrouter_model="unused", allowed_origins=(), runtime_dir=tmp_path,
        evidence_collector_token="test-collector-private-token",
    ), repository=Repository()))

    with TestClient(application) as client:
        class Opener:
            def open(self, request, timeout):
                path = uploader.urllib.parse.urlsplit(request.full_url).path
                result = client.request(request.method, path, content=request.data, headers=dict(request.header_items()))
                response = Response(request)
                response.status = result.status_code
                response.payload = result.json()
                return response

        monkeypatch.setattr(uploader.urllib.request, "build_opener", lambda *args: Opener())
        summary = uploader.upload_capture(*IDENTITY)

    assert summary["status"] == "uploaded"
    assert len(stored) == len(list(capture.iterdir()))
    for filename, (metadata, data) in stored.items():
        assert metadata["sha256"] == hashlib.sha256(data).hexdigest()
        assert metadata["original_sha256"] == hashlib.sha256((capture / filename).read_bytes()).hexdigest()
        assert b"artifact-test-secret" not in data
        assert metadata["event_id"] == summary["capture_event_id"]

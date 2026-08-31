from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime_agent import recon_tools


RUN_ID = "os-123456789abc"
ACTION_ID = "action-current"


def record(*, run_id: str = RUN_ID, action_id: str = ACTION_ID, **fields) -> str:
    return json.dumps(
        {"run_id": run_id, "action_id": action_id, **fields},
        ensure_ascii=False,
    )


def digest(line: str) -> str:
    return "sha256:" + hashlib.sha256(line.encode("utf-8")).hexdigest()


@pytest.fixture
def evidence_files(monkeypatch, tmp_path):
    # Route only the existing fixed evidence paths into test-owned files. These
    # tests call the lookup helper and do not require Linux process identities.
    monkeypatch.setattr(recon_tools, "Path", lambda value: tmp_path / Path(value).name)
    return tmp_path


def test_finds_current_run_beyond_old_prefix_and_sparse_recent_records(evidence_files):
    old = record(run_id="os-aaaaaaaaaaaa", padding="x" * 60)
    current = record(message="current run evidence")
    content = ((old + "\n") * 100 + current + "\n" + (old + "\n") * 1200)
    assert content.index(current) > 4096
    (evidence_files / "state-captures.ndjson").write_bytes(content.encode("utf-8"))

    result = recon_tools._evidence_file_query(RUN_ID, 32)

    assert result["record_sha256"] == [digest(current)]
    assert result["match_count"] == 1
    assert result["raw_records_exposed"] is False
    assert result["scan"]["history_truncated"] is False
    assert current not in json.dumps(result)


def test_returns_newest_matching_records_and_preserves_exact_ids(evidence_files):
    oldest = record(sequence=1)
    middle = record(sequence=2)
    newest = record(sequence=3)
    unrelated_run = record(run_id=RUN_ID + "0")
    unrelated_action = record(action_id=ACTION_ID + "0")
    content = "\n".join([oldest, middle, newest, unrelated_run, unrelated_action]) + "\n"
    (evidence_files / "state-captures.ndjson").write_bytes(content.encode("utf-8"))

    result = recon_tools._evidence_file_query(RUN_ID, 2, action_id=ACTION_ID)

    assert result["record_sha256"] == [digest(newest), digest(middle)]
    assert result["match_count"] == 2
    assert result["scan"]["result_limit_reached"] is True


def test_legacy_text_records_match_complete_run_and_action_ids(evidence_files):
    valid = json.dumps({"message": f"run_id={RUN_ID} action_id={ACTION_ID}"})
    unrelated = [
        f"run_id={RUN_ID}0 action_id={ACTION_ID}",
        f"run_id={RUN_ID} action_id={ACTION_ID}0",
        f"previous_run_id={RUN_ID} action_id={ACTION_ID}",
        f"run_id={RUN_ID} previous_action_id={ACTION_ID}",
    ]
    (evidence_files / "state-captures.ndjson").write_bytes(
        ("\n".join([valid, *unrelated]) + "\n").encode()
    )

    result = recon_tools._evidence_file_query(RUN_ID, 32, action_id=ACTION_ID)

    assert result["record_sha256"] == [digest(valid)]


def test_result_limit_is_shared_across_existing_evidence_files(evidence_files):
    state = record(source="state")
    docker_old = record(source="docker", sequence=1)
    docker_new = record(source="docker", sequence=2)
    (evidence_files / "state-captures.ndjson").write_bytes((state + "\n").encode())
    (evidence_files / "docker-events.ndjson").write_bytes(
        (docker_old + "\n" + docker_new + "\n").encode()
    )
    (evidence_files / "docker-logs.ndjson").write_bytes((record(source="logs") + "\n").encode())

    result = recon_tools._evidence_file_query(RUN_ID, 2)

    assert result["record_sha256"] == [digest(state), digest(docker_new)]
    assert result["scan"]["files_scanned"] == 2


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_keeps_complete_record_at_exact_window_boundary(monkeypatch, evidence_files, newline):
    current = record(message="최근 증거")
    current_bytes = (current + newline).encode("utf-8")
    old_bytes = (record(run_id="os-aaaaaaaaaaaa") + newline).encode("utf-8")
    (evidence_files / "state-captures.ndjson").write_bytes(old_bytes + current_bytes)
    monkeypatch.setattr(recon_tools, "EVIDENCE_SCAN_WINDOW_BYTES", len(current_bytes))

    result = recon_tools._evidence_file_query(RUN_ID, 32)

    assert result["record_sha256"] == [digest(current)]
    assert result["scan"]["history_truncated"] is True
    assert result["scan"]["partial_lines_skipped"] == 0
    assert result["scan"]["bytes_read"] == len(current_bytes) + 1


def test_skips_partial_utf8_prefix_and_in_progress_last_line(monkeypatch, evidence_files):
    old_bytes = (record(run_id="os-aaaaaaaaaaaa", message="한글" * 30) + "\n").encode("utf-8")
    current = record(message="현재 로그 🔎")
    current_bytes = (current + "\r\n").encode("utf-8")
    incomplete = ('{"run_id":"' + RUN_ID + '","action_id":"' + ACTION_ID + '"').encode()
    content = old_bytes + current_bytes + incomplete
    start_inside_utf8 = old_bytes.index("한".encode("utf-8")) + 1
    monkeypatch.setattr(recon_tools, "EVIDENCE_SCAN_WINDOW_BYTES", len(content) - start_inside_utf8)
    (evidence_files / "state-captures.ndjson").write_bytes(content)

    result = recon_tools._evidence_file_query(RUN_ID, 32)

    assert result["record_sha256"] == [digest(current)]
    assert result["scan"]["history_truncated"] is True
    assert result["scan"]["partial_lines_skipped"] == 2


@pytest.mark.parametrize("ending", [b"\n", b""])
def test_oversized_line_is_not_misread_as_an_evidence_fragment(monkeypatch, evidence_files, ending):
    # The suffix deliberately resembles a matching legacy text event. It must
    # not be accepted after the beginning of this oversized record is dropped.
    line = b"x" * 1024 + f" run_id={RUN_ID} action_id={ACTION_ID}".encode() + ending
    (evidence_files / "state-captures.ndjson").write_bytes(line)
    monkeypatch.setattr(recon_tools, "EVIDENCE_SCAN_WINDOW_BYTES", 128)

    result = recon_tools._evidence_file_query(RUN_ID, 32)

    assert result["match_count"] == 0
    assert result["scan"]["history_truncated"] is True
    assert result["scan"]["partial_lines_skipped"] == 1
    assert result["scan"]["bytes_read"] == 129


def test_missing_or_empty_logs_return_an_explicit_empty_scan(evidence_files):
    (evidence_files / "state-captures.ndjson").write_bytes(b"")

    result = recon_tools._evidence_file_query(RUN_ID, 32)

    assert result["record_sha256"] == []
    assert result["scan"]["files_scanned"] == 1
    assert result["scan"]["bytes_read"] == 0
    assert result["scan"]["history_truncated"] is False
    assert result["scan"]["result_limit_reached"] is False


@pytest.mark.parametrize("error_type", [FileNotFoundError, NotADirectoryError])
def test_log_rotation_does_not_prevent_other_sources_being_read(monkeypatch, evidence_files, error_type):
    rotating = evidence_files / "state-captures.ndjson"
    rotating.write_bytes(b"old\n")
    current = record(source="docker")
    (evidence_files / "docker-events.ndjson").write_bytes((current + "\n").encode())
    original_open = Path.open

    def open_after_rotation(path, *args, **kwargs):
        if path == rotating:
            raise error_type("log rotated")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", open_after_rotation)

    result = recon_tools._evidence_file_query(RUN_ID, 32)

    assert result["record_sha256"] == [digest(current)]
    assert result["scan"]["files_scanned"] == 1


def test_correlate_reports_the_same_scan_limits(evidence_files):
    current = record()
    (evidence_files / "state-captures.ndjson").write_bytes((current + "\n").encode())

    result = recon_tools._audit_data(
        "os_evidence_correlate", {}, {"run_id": RUN_ID, "action_id": ACTION_ID}
    )

    assert result["correlated"] is True
    assert result["evidence_refs"] == [f"evidence:{digest(current)}"]
    assert result["raw_records_exposed"] is False
    assert result["scan"]["mode"] == "recent_window"
    assert result["scan"]["window_bytes_per_file"] == recon_tools.EVIDENCE_SCAN_WINDOW_BYTES

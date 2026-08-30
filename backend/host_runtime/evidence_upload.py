"""One-shot upload of an existing, completed state capture; never collects state."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import urllib.error
import urllib.parse
import urllib.request
import uuid

try:  # Bootstrap installs this helper beside the host-side uploader.
    from evidence_security import ARTIFACT_FILENAMES, redact_artifact
except ImportError:
    from app.evidence_security import ARTIFACT_FILENAMES, redact_artifact


ROOT = Path("/var/lib/os-agent/evidence/runs")
CONFIG_PATH = Path("/etc/os-agent/evidence-upload.json")
TOKEN_FILE = Path("/etc/vector/secrets/collector_token")
EVENT_FILE = Path("/var/log/os-agent/state-captures.ndjson")
LOCK_FILE = Path("/var/lib/os-agent/state-event.lock")
MAX_FILE_BYTES = 32 * 1024 * 1024
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PATH_TARGETS = {
    "U1C1": "C1", "U1C2": "C2", "U1U2": "U2", "U1C3": "C3",
    "C1U1": "U1", "C1C2": "C2", "C1U2": "U2", "C1C3": "C3",
}
COMMON_FILES = {
    "timestamp_utc.txt", "boot_id.txt", "journal_cursor.txt", "audit_status.txt",
    "processes.txt", "listeners.txt", "files.sha256", "files.metadata", "manifest.json",
}


class UploadFailure(Exception):
    """Only constant, non-sensitive error codes leave the uploader."""


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _no_symlinks(path: Path) -> None:
    if not path.is_absolute():
        raise UploadFailure("unsafe_artifact_path")
    for part in [*reversed(path.parents), path]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        ):
            raise UploadFailure("unsafe_artifact_path")


def _read_regular(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    _no_symlinks(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UploadFailure("unsafe_artifact_path")
        if info.st_size > limit:
            raise UploadFailure("artifact_too_large")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise UploadFailure("artifact_too_large")
    return data


def _configuration() -> dict | None:
    try:
        config = json.loads(_read_regular(CONFIG_PATH, 16 * 1024))
    except FileNotFoundError:
        return None
    except (ValueError, UnicodeError):
        raise UploadFailure("invalid_upload_configuration") from None
    if not isinstance(config, dict) or not isinstance(config.get("enabled"), bool):
        raise UploadFailure("invalid_upload_configuration")
    if not config["enabled"]:
        return None
    api_url = config.get("api_url")
    environment_id = config.get("environment_id")
    if not isinstance(api_url, str) or not isinstance(environment_id, str):
        raise UploadFailure("invalid_upload_configuration")
    parsed = urllib.parse.urlsplit(api_url)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username
        or parsed.password or parsed.query or parsed.fragment
        or any(ord(char) < 33 for char in api_url)
        or not SAFE_ID.fullmatch(environment_id)
        or config.get("token_file") != str(TOKEN_FILE)
    ):
        raise UploadFailure("invalid_upload_configuration")
    config["api_url"] = api_url.rstrip("/")
    return config


def _capture(context: dict, summary: dict) -> tuple[str, dict[str, bytes]]:
    capture_dir = ROOT / context["run_id"] / "actions" / context["action_id"] / context["phase"]
    _no_symlinks(capture_dir)
    index = _read_regular(capture_dir / "artifact-sha256.txt", 16 * 1024)
    event_id = "state-" + hashlib.sha256(index).hexdigest()
    summary["capture_event_id"] = event_id
    try:
        index_text = index.decode("ascii")
    except UnicodeError:
        raise UploadFailure("invalid_artifact_index") from None
    indexed = {}
    for line in index_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./([A-Za-z0-9._-]+)", line)
        if not match or match[2] in indexed or match[2] == "artifact-sha256.txt":
            raise UploadFailure("invalid_artifact_index")
        if match[2] not in ARTIFACT_FILENAMES:
            raise UploadFailure("invalid_artifact_index")
        indexed[match[2]] = match[1]
    expected = COMMON_FILES | (
        {"identity.txt", "target_processes.txt"} if context["target_id"] in {"U1", "U2"}
        else {"container_inspect.json", "container_processes.txt", "container_diff.txt"}
    )
    if context["phase"] == "after":
        expected |= {"diff-from-before.txt"}
    if set(indexed) != expected or {item.name for item in capture_dir.iterdir()} != expected | {"artifact-sha256.txt"}:
        raise UploadFailure("invalid_artifact_index")
    files = {}
    for filename, checksum in indexed.items():
        data = _read_regular(capture_dir / filename)
        if hashlib.sha256(data).hexdigest() != checksum:
            raise UploadFailure("artifact_integrity_failed")
        files[filename] = data
    try:
        manifest = json.loads(files["manifest.json"])
    except (ValueError, UnicodeError):
        raise UploadFailure("artifact_manifest_mismatch") from None
    if (
        not isinstance(manifest, dict) or manifest.get("schema_version") != "state-capture-v1"
        or manifest.get("status") != "COMPLETE"
        or any(manifest.get(key) != value for key, value in context.items())
    ):
        raise UploadFailure("artifact_manifest_mismatch")
    files["artifact-sha256.txt"] = index
    return event_id, files


def _upload(config: dict, context: dict, event_id: str, filename: str, original: bytes, token: str) -> dict:
    try:
        data = redact_artifact(original, filename)
    except (ValueError, UnicodeError, RecursionError):
        raise UploadFailure("artifact_redaction_failed") from None
    if len(data) > MAX_FILE_BYTES:
        raise UploadFailure("artifact_too_large")
    checksum = hashlib.sha256(data).hexdigest()
    original_checksum = hashlib.sha256(original).hexdigest()
    components = [context["run_id"], context["action_id"], context["phase"], filename]
    suffix = "/".join(urllib.parse.quote(value, safe="") for value in components)
    request = urllib.request.Request(
        config["api_url"] + "/internal/evidence/artifacts/" + suffix,
        data=data,
        method="PUT",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/octet-stream",
            "X-Evidence-Event-Id": event_id,
            "X-Evidence-Environment-Id": config["environment_id"],
            "X-Evidence-SHA256": checksum,
            "X-Evidence-Original-SHA256": original_checksum,
        },
    )
    try:
        with urllib.request.build_opener(NoRedirects()).open(request, timeout=30) as response:
            if response.status not in {200, 201}:
                raise UploadFailure("artifact_http_failure")
            body = response.read(65537)
            if len(body) > 65536:
                raise UploadFailure("invalid_upload_response")
    except urllib.error.HTTPError as error:
        error.close()
        raise UploadFailure("artifact_http_failure") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise UploadFailure("artifact_http_failure") from None
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError):
        raise UploadFailure("invalid_upload_response") from None
    expected = {
        "status": "uploaded", "event_id": event_id, "filename": filename,
        "size_bytes": len(data), "sha256": checksum, "original_sha256": original_checksum,
    }
    if (
        not isinstance(result, dict)
        or any(result.get(key) != value for key, value in expected.items())
        or type(result.get("size_bytes")) is not int
        or not isinstance(result.get("bucket"), str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", result["bucket"])
        or not isinstance(result.get("object_path"), str)
        or not re.fullmatch(r"[A-Za-z0-9._/-]{1,1024}", result["object_path"])
    ):
        raise UploadFailure("invalid_upload_response")
    return {**expected, "bucket": result["bucket"], "object_path": result["object_path"]}


def upload_capture(run_id: str, action_id: str, phase: str, path_id: str, target_id: str) -> dict | None:
    """Return a summary only; disabled configuration performs no HTTP or capture reads."""
    context = dict(run_id=run_id, action_id=action_id, phase=phase, path_id=path_id, target_id=target_id)
    if (
        not SAFE_ID.fullmatch(run_id) or not SAFE_ID.fullmatch(action_id)
        or phase not in {"before", "after"} or PATH_TARGETS.get(path_id) != target_id
    ):
        raise UploadFailure("invalid_capture_identity")
    summary = {
        "event_id": "artifact-" + uuid.uuid4().hex,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "source": "snapshot-runner",
        "event_type": "ARTIFACT_UPLOAD_FAILED",
        "message": "state capture artifact upload failed",
        **context,
        "capture_event_id": None,
        "collection_error": True,
        "status": "failed",
        "artifacts": [],
    }
    try:
        config = _configuration()
        if config is None:
            return None
        event_id, files = _capture(context, summary)
        summary["expected_artifact_count"] = len(files)
        token = _read_regular(TOKEN_FILE, 4096).decode("ascii").strip()
        if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise UploadFailure("invalid_collector_token")
        for filename in sorted(files):
            summary["failed_filename"] = filename
            summary["artifacts"].append(_upload(config, context, event_id, filename, files[filename], token))
        summary.pop("failed_filename", None)
        summary.update(
            event_type="ARTIFACT_UPLOADED", status="uploaded", collection_error=False,
            message="state capture artifacts uploaded",
        )
    except UploadFailure as error:
        summary["error_code"] = str(error)
    except Exception:
        summary["error_code"] = "artifact_upload_failed"
    summary["uploaded_artifact_count"] = len(summary["artifacts"])
    return summary


def _append_summary(summary: dict) -> None:
    # Shares the capture script's flock; append-open follows its existing rotation.
    try:
        import fcntl
    except ImportError:  # The producer runs on Linux; permits isolated Windows tests.
        fcntl = None
    _no_symlinks(EVENT_FILE.parent)
    _no_symlinks(LOCK_FILE.parent)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(LOCK_FILE, flags, 0o640)
    try:
        if fcntl is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        event_fd = os.open(EVENT_FILE, flags | os.O_APPEND, 0o640)
        try:
            if not stat.S_ISREG(os.fstat(event_fd).st_mode):
                raise UploadFailure("unsafe_event_log")
            line = (json.dumps(summary, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
            while line:
                line = line[os.write(event_fd, line):]
        finally:
            os.close(event_fd)
    finally:
        os.close(lock_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run_id", "action_id", "phase", "path_id", "target_id"):
        parser.add_argument(name)
    args = parser.parse_args(argv)
    try:
        summary = upload_capture(**vars(args))
        if summary is None:
            return 0
        _append_summary(summary)
        return 0 if summary["status"] == "uploaded" else 1
    except Exception:
        # Never print exception bodies: transports can include credentials or raw data.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

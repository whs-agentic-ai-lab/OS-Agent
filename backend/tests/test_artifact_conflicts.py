"""Immutable artifact conflict/retry checks; no remote DB or Storage is used."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from hashlib import sha256
import json
import threading
from types import SimpleNamespace

import httpx
import pytest
from storage3.exceptions import StorageApiError
from supabase import ClientOptions, create_client

from app.evidence import ARTIFACT_BUCKET, EvidenceConflict, SupabaseEvidenceRepository
from test_evidence import (
    ARTIFACT_URL, SECRET, FakeQuery, FakeStorage, FakeSupabase,
    artifact_headers, client_for,
)


def reference(body, **updates):
    digest = sha256(body).hexdigest()
    result = {
        "environment_id": "e2e-test-env", "event_id": "state-test-event",
        "run_id": "test-run-1", "action_id": "test-action-1", "phase": "before",
        "filename": "processes.txt", "bucket": ARTIFACT_BUCKET,
        "size_bytes": len(body), "sha256": digest, "original_sha256": digest,
        "status": "uploaded", **updates,
    }
    result["object_path"] = (
        f"{result['environment_id']}/{result['run_id']}/{result['action_id']}/"
        f"{result['phase']}/{result['event_id']}/{result['sha256']}/{result['filename']}"
    )
    return result


def row_key(metadata):
    return tuple(metadata[key] for key in ("environment_id", "event_id", "filename"))


def repository(db):
    return SupabaseEvidenceRepository("https://example.supabase.co", "test-only", client=db)


class ConcurrentQuery(FakeQuery):
    def execute(self):
        if self.values is not None and self.client.before_write:
            self.client.before_write(self.values[0])
        # Mimic the DB unique constraint atomically, across distinct repository
        # instances. Interleaving hooks run outside that transaction/lock.
        with self.client.lock:
            result = super().execute()
        callback = self.client.after_write if self.values is not None else self.client.after_read
        if callback:
            callback(self, result)
        return result


class ConcurrentStorage(FakeStorage):
    def __init__(self, db):
        super().__init__()
        self.db = db

    def upload(self, path, data, *, file_options):
        if self.db.before_upload:
            self.db.before_upload(path)
        with self.db.lock:
            result = super().upload(path, data, file_options=file_options)
        if self.db.after_upload:
            self.db.after_upload(path)
        return result

    def remove(self, paths):
        with self.db.lock:
            result = super().remove(paths)
        if self.db.after_remove:
            self.db.after_remove(paths)
        return result


class ConcurrentSupabase(FakeSupabase):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.role = threading.local()
        self.storage = ConcurrentStorage(self)
        self.after_read = self.before_write = self.after_write = None
        self.before_upload = self.after_upload = self.after_remove = None

    def table(self, name):
        return ConcurrentQuery(self, name)

    def synchronize_initial_reads(self, count):
        barrier = threading.Barrier(count, timeout=5)

        def after_read(query, result):
            if query.table_name == "evidence_artifacts" and not result.data:
                barrier.wait()

        self.after_read = after_read


def save_as(db, role, metadata, body):
    db.role.name = role
    try:
        return 200, repository(db).save_artifact(metadata, body)
    except EvidenceConflict:
        return 409, None


@pytest.mark.parametrize("variant", ["different_content", "same_content", "same_path_metadata_conflict"])
def test_concurrent_uploads_keep_only_the_immutable_winner(variant):
    db = ConcurrentSupabase()
    db.synchronize_initial_reads(2)
    uploads = threading.Barrier(2, timeout=5)
    db.after_upload = lambda _path: uploads.wait()
    first = b"first content"
    second = b"different content" if variant == "different_content" else first
    metadata = [reference(first), reference(second)]
    if variant == "same_path_metadata_conflict":
        metadata[1]["original_sha256"] = sha256(b"different unredacted content").hexdigest()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(save_as, db, str(index), item, body)
            for index, (item, body) in enumerate(zip(metadata, [first, second]))
        ]
        results = [future.result(timeout=10) for future in futures]
    assert sorted(code for code, _ in results) == ([200, 200] if variant == "same_content" else [200, 409])
    assert len(db.rows["evidence_artifacts"]) == len(db.storage.objects) == 1
    winner = next(iter(db.rows["evidence_artifacts"].values()))
    assert winner["object_path"] in db.storage.objects
    assert sha256(db.storage.objects[winner["object_path"]]).hexdigest() == winner["sha256"]
    if variant != "different_content":
        assert db.storage.remove_calls == []


def test_late_concurrent_loser_upload_is_cleaned_after_another_loser_finished():
    db = ConcurrentSupabase()
    db.synchronize_initial_reads(3)
    winner_committed = threading.Event()
    earlier_cleanup_done = threading.Event()
    first, second = b"winner", b"loser"

    def before_upload(_path):
        if db.role.name == "late-loser":
            assert earlier_cleanup_done.wait(timeout=5)

    def before_write(_metadata):
        if db.role.name != "winner":
            assert winner_committed.wait(timeout=5)

    def after_write(_query, _result):
        if db.role.name == "winner":
            winner_committed.set()

    def after_remove(_paths):
        if db.role.name == "early-loser":
            earlier_cleanup_done.set()

    db.before_upload, db.before_write = before_upload, before_write
    db.after_write, db.after_remove = after_write, after_remove
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [
            pool.submit(save_as, db, role, reference(body), body)
            for role, body in [("winner", first), ("early-loser", second), ("late-loser", second)]
        ]
        assert [future.result(timeout=10)[0] for future in futures] == [200, 409, 409]
    assert db.storage.objects == {reference(first)["object_path"]: first}
    assert db.storage.remove_calls == [[reference(second)["object_path"]]] * 2


def test_cleanup_failure_is_retryable_and_precheck_retry_removes_prior_orphan(tmp_path, monkeypatch):
    client, db = client_for(tmp_path)
    first, second = b"winner", b"loser"
    winner, loser = reference(first), reference(second)
    real_upload, real_remove = db.storage.upload, db.storage.remove

    def racing_upload(path, data, *, file_options):
        real_upload(path, data, file_options=file_options)
        # Another API worker commits the winning immutable row after this
        # request's precheck and upload, but before its upsert.
        db.rows["evidence_artifacts"][row_key(winner)] = deepcopy(winner)
        db.storage.objects[winner["object_path"]] = first

    def failed_remove(_paths):
        raise RuntimeError("failed cleanup password=" + SECRET)

    monkeypatch.setattr(db.storage, "upload", racing_upload)
    monkeypatch.setattr(db.storage, "remove", failed_remove)
    response = client.put(ARTIFACT_URL, content=second, headers=artifact_headers(second))
    assert response.status_code == 503
    assert SECRET not in response.text
    assert set(db.storage.objects) == {winner["object_path"], loser["object_path"]}
    monkeypatch.setattr(db.storage, "remove", real_remove)
    response = client.put(ARTIFACT_URL, content=second, headers=artifact_headers(second))
    assert response.status_code == 409
    assert db.storage.upload_count == 1
    assert db.storage.objects == {winner["object_path"]: first}
    assert db.rows["evidence_artifacts"][row_key(winner)] == winner


def test_metadata_failure_then_different_winner_is_cleaned_on_conflicting_retry(tmp_path):
    client, db = client_for(tmp_path)
    first, second = b"failed upload attempt", b"different committed capture"
    db.fail_metadata_once = True
    assert client.put(ARTIFACT_URL, content=first, headers=artifact_headers(first)).status_code == 503
    assert client.put(ARTIFACT_URL, content=second, headers=artifact_headers(second)).status_code == 200
    assert len(db.storage.objects) == 2
    assert client.put(ARTIFACT_URL, content=first, headers=artifact_headers(first)).status_code == 409
    assert db.storage.objects == {reference(second)["object_path"]: second}


@pytest.mark.parametrize("failure", ["commit_response_lost", "post_commit_read_failed", "precheck_failed"])
def test_uncertain_db_failures_never_delete_objects_and_retry_is_safe(tmp_path, monkeypatch, failure):
    client, db = client_for(tmp_path)
    real_execute = FakeQuery.execute
    failed = False
    body = b"capture with uncertain DB response"

    def execute(query):
        nonlocal failed
        if query.table_name != "evidence_artifacts":
            return real_execute(query)
        if not failed and failure == "precheck_failed" and query.values is None:
            failed = True
            raise RuntimeError("DB unavailable password=" + SECRET)
        result = real_execute(query)
        if not failed and (
            (failure == "commit_response_lost" and query.values is not None)
            or (failure == "post_commit_read_failed" and query.values is None and result.data)
        ):
            failed = True
            raise RuntimeError("DB response lost password=" + SECRET)
        return result

    monkeypatch.setattr(FakeQuery, "execute", execute)
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 503
    assert SECRET not in response.text
    assert db.storage.remove_calls == []
    assert len(db.storage.objects) == (0 if failure == "precheck_failed" else 1)
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 200
    assert db.storage.upload_count == 1
    assert len(db.storage.objects) == len(db.rows["evidence_artifacts"]) == 1
    assert db.storage.remove_calls == []


def test_storage_duplicate_error_does_not_delete_an_existing_object(tmp_path, monkeypatch):
    client, db = client_for(tmp_path)
    body = b"previous upload before metadata write"
    path = reference(body)["object_path"]
    db.storage.objects[path] = body
    original_upload = db.storage.upload

    def duplicate(*_args, **_kwargs):
        raise StorageApiError("duplicate password=" + SECRET, "Duplicate", 409)

    monkeypatch.setattr(db.storage, "upload", duplicate)
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 503
    assert SECRET not in response.text
    assert not db.rows["evidence_artifacts"]
    assert db.storage.objects == {path: body}
    assert db.storage.remove_calls == []
    monkeypatch.setattr(db.storage, "upload", original_upload)
    assert client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body)).status_code == 200
    assert db.storage.objects == {path: body}


def test_same_masked_content_metadata_conflict_keeps_shared_object(tmp_path):
    client, db = client_for(tmp_path)
    bodies = [b"--password=first-secret", b"--password=second-secret"]
    for index, body in enumerate(bodies):
        response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
        assert response.status_code == (200 if index == 0 else 409)
    assert len(db.storage.objects) == 1
    assert next(iter(db.storage.objects.values())) == b"--password=[REDACTED]"
    assert db.storage.remove_calls == []
    assert db.storage.upload_count == 1


@pytest.mark.parametrize("field,value", [
    ("environment_id", "other-env"), ("event_id", "other:event"), ("filename", "listeners.txt"),
])
def test_conflict_cannot_target_a_different_immutable_keys_object(field, value):
    db = FakeSupabase()
    body = b"same content in distinct keys"
    winner = reference(body, **{field: value})
    repository(db).save_artifact(winner, body)
    invalid = reference(body)
    invalid["object_path"] = winner["object_path"]
    with pytest.raises(ValueError, match="Invalid content-addressed artifact reference"):
        repository(db).save_artifact(invalid, body)
    assert db.storage.objects == {winner["object_path"]: body}
    assert db.storage.remove_calls == []


@pytest.mark.parametrize("field", ["environment_id", "run_id", "action_id", "event_id", "filename", "phase", "sha256"])
def test_path_segments_are_validated_before_storage_operations(field):
    db = FakeSupabase()
    body = b"capture"
    invalid = reference(body, **{field: "../another-object"})
    with pytest.raises(ValueError, match="Invalid content-addressed artifact path"):
        repository(db).save_artifact(invalid, body)
    assert db.storage.upload_count == 0
    assert db.storage.remove_calls == []


@pytest.mark.parametrize("inconsistency", ["different_key", "different_path"])
def test_inconsistent_db_reference_is_not_proof_for_cleanup(monkeypatch, inconsistency):
    db = FakeSupabase()
    first, second = b"winner", b"loser"
    winner, loser = reference(first), reference(second)
    if inconsistency == "different_key":
        winner = reference(first, environment_id="other-env")
    else:
        winner["object_path"] = reference(first, environment_id="other-env")["object_path"]
    db.storage.objects[winner["object_path"]] = first
    db.storage.objects[loser["object_path"]] = second
    monkeypatch.setattr(FakeQuery, "execute", lambda _self: SimpleNamespace(data=[winner]))
    with pytest.raises(RuntimeError, match="Invalid persisted artifact reference"):
        repository(db).save_artifact(loser, second)
    assert len(db.storage.objects) == 2
    assert db.storage.remove_calls == []


def test_real_sdk_conflict_cleanup_is_exact_private_object_delete_and_retryable():
    first, second = b"winner", b"loser"
    winner, loser = reference(first), reference(second)
    objects = {winner["object_path"]: first, loser["object_path"]: second}
    attempts = 0

    def handle(request):
        nonlocal attempts
        path = request.url.path
        if path == "/storage/v1/bucket/" + ARTIFACT_BUCKET:
            assert request.method == "GET"
            return httpx.Response(200, json={
                "id": ARTIFACT_BUCKET, "name": ARTIFACT_BUCKET, "owner": "test-only",
                "public": False, "created_at": "2026-08-30T00:00:00Z",
                "updated_at": "2026-08-30T00:00:00Z", "file_size_limit": 33554432,
                "allowed_mime_types": None,
            })
        if path == "/rest/v1/evidence_artifacts":
            assert request.method == "GET"
            for key in ("environment_id", "event_id", "filename"):
                assert request.url.params[key] == "eq." + loser[key]
            return httpx.Response(200, json=[winner])
        if path == "/storage/v1/object/" + ARTIFACT_BUCKET:
            assert request.method == "DELETE"
            assert json.loads(request.content) == {"prefixes": [loser["object_path"]]}
            attempts += 1
            if attempts == 1:
                return httpx.Response(503, json={
                    "statusCode": "503", "error": "Unavailable", "message": "test-only failure",
                })
            objects.pop(loser["object_path"], None)
            return httpx.Response(200, json=[])
        pytest.fail("Unexpected SDK request: " + request.method + " " + path)

    with httpx.Client(transport=httpx.MockTransport(handle)) as transport:
        sdk = create_client(
            "https://example.supabase.co", "test-server-secret",
            options=ClientOptions(httpx_client=transport, auto_refresh_token=False, persist_session=False),
        )
        target = SupabaseEvidenceRepository("https://example.supabase.co", "unused", client=sdk)
        with pytest.raises(StorageApiError):
            target.save_artifact(loser, second)
        assert len(objects) == 2
        with pytest.raises(EvidenceConflict):
            target.save_artifact(loser, second)
    assert attempts == 2
    assert objects == {winner["object_path"]: first}

from copy import deepcopy
import gzip
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest
from supabase import ClientOptions, create_client

from app.config import Settings, get_settings
from app.evidence import (
    ARTIFACT_BUCKET,
    EvidenceEvent,
    SupabaseEvidenceRepository,
    create_evidence_router,
)
from app.evidence_security import ARTIFACT_FILENAMES, redact, redact_artifact, redact_text


TOKEN = "test-collector-secret"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/x-ndjson"}
SECRET = "never-include-this-secret"


def event(**updates) -> dict:
    return {
        "schema_version": "os-agent-evidence-v1",
        "event_id": "test-event-1",
        "source_type": "executor",
        "source": "verifier",
        "event_type": "TOOL_VERIFIED",
        "occurred_at": "2026-08-30T01:00:00Z",
        "collector_received_at": "2026-08-30T01:00:01Z",
        "environment_id": "e2e-test-env",
        "topology_revision": "fixed-v1",
        "message": "verification completed",
        "collector": {"channel": "executor", "file_offset": 42},
        "payload": {
            "tool_result": {"outcome": "OS_DENIED", "exit_code": 13},
            "verification": {"status": "VERIFIED", "checks": {"denial_expected": True}},
        },
        "context": {"run_id": "test-run-1", "action_id": "test-action-1", "step_id": None, "tool_call_id": None},
        "status": "ok",
        **updates,
    }


def ndjson(*events: dict) -> bytes:
    return ("\n".join(json.dumps(item) for item in events) + "\n").encode()


class FakeQuery:
    def __init__(self, client, table):
        self.client = client
        self.table_name = table
        self.values = None
        self.filters = {}

    def upsert(self, values, *, on_conflict, ignore_duplicates):
        assert ignore_duplicates is True
        expected = "environment_id,event_id" if self.table_name == "evidence_events" else "environment_id,event_id,filename"
        assert on_conflict == expected
        self.values = values if isinstance(values, list) else [values]
        self.keys = on_conflict.split(",")
        return self

    def select(self, _columns):
        return self

    def eq(self, key, value):
        self.filters[key] = value
        return self

    def limit(self, _limit):
        return self

    def execute(self):
        if self.values is not None:
            if self.table_name == "evidence_events" and self.client.fail_events:
                raise RuntimeError("password=" + SECRET)
            if self.table_name == "evidence_artifacts" and self.client.fail_metadata_once:
                self.client.fail_metadata_once = False
                raise RuntimeError("api_key=" + SECRET)
            inserted = []
            for value in self.values:
                key = tuple(value[field] for field in self.keys)
                if key not in self.client.rows[self.table_name]:
                    self.client.rows[self.table_name][key] = deepcopy(value)
                    inserted.append(value)
            return SimpleNamespace(data=inserted)
        return SimpleNamespace(data=[
            deepcopy(value) for value in self.client.rows[self.table_name].values()
            if all(value.get(key) == item for key, item in self.filters.items())
        ])


class FakeStorage:
    def __init__(self):
        self.public = False
        self.fail_upload = False
        self.objects = {}
        self.upload_count = 0

    def get_bucket(self, name):
        assert name == ARTIFACT_BUCKET
        return SimpleNamespace(public=self.public)

    def from_(self, name):
        assert name == ARTIFACT_BUCKET
        return self

    def upload(self, path, data, *, file_options):
        if self.fail_upload:
            raise RuntimeError("Authorization: Bearer " + SECRET)
        assert file_options["upsert"] == "true"
        assert ".." not in path.split("/")
        self.upload_count += 1
        self.objects[path] = data


class FakeSupabase:
    def __init__(self):
        self.rows = {"evidence_events": {}, "evidence_artifacts": {}}
        self.storage = FakeStorage()
        self.fail_events = False
        self.fail_metadata_once = False

    def table(self, name):
        assert name in self.rows
        return FakeQuery(self, name)


def settings(tmp_path, **updates) -> Settings:
    return Settings(
        openrouter_api_key=None,
        openrouter_model="test-model",
        allowed_origins=(),
        runtime_dir=tmp_path,
        **{"evidence_collector_token": TOKEN, **updates},
    )


def client_for(tmp_path, db=None, **updates):
    db = db or FakeSupabase()
    repository = SupabaseEvidenceRepository("https://example.supabase.co", "server-secret", client=db)
    application = FastAPI()
    application.include_router(create_evidence_router(settings(tmp_path, **updates), repository))
    return TestClient(application), db


@pytest.mark.parametrize("compressed", [False, True])
def test_accepts_vector_ndjson_and_preserves_context_verifier_results(tmp_path, compressed):
    client, db = client_for(tmp_path)
    sample = event()
    data = ndjson(sample)
    headers = dict(HEADERS)
    if compressed:
        data = gzip.compress(data)
        headers["Content-Encoding"] = "gzip"
    response = client.post("/internal/evidence/events", content=data, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"accepted": 1}
    stored = next(iter(db.rows["evidence_events"].values()))
    assert stored["context"] == sample["context"]
    assert stored["payload"]["tool_result"]["outcome"] == "OS_DENIED"
    assert stored["payload"]["verification"]["status"] == "VERIFIED"
    assert stored["payload"]["verification"]["checks"] == {"denial_expected": True}


def test_omitted_v1_context_and_status_remain_explicitly_unknown():
    sample = event()
    del sample["context"], sample["status"]
    sample["payload"]["message"] = "run_id=do-not-infer"
    parsed = EvidenceEvent.model_validate(sample)
    assert parsed.context.model_dump() == dict.fromkeys(["run_id", "action_id", "step_id", "tool_call_id"])
    assert parsed.status == "ok"


@pytest.mark.parametrize("status", ["parse_error", "collection_error"])
def test_buffered_v1_explicit_failure_flags_do_not_become_normal(status):
    sample = event(payload={status: True, "raw_message": "unparseable"})
    del sample["status"], sample["context"]
    parsed = EvidenceEvent.model_validate(sample)
    assert parsed.status == status
    assert parsed.context.run_id is None


@pytest.mark.parametrize("authorization", [None, "Bearer wrong-token", "Basic test-collector-secret"])
def test_bad_auth_rejected_without_secret_echo(tmp_path, authorization):
    client, db = client_for(tmp_path)
    headers = {"Content-Type": "application/x-ndjson"}
    if authorization:
        headers["Authorization"] = authorization
    response = client.post("/internal/evidence/events", content=ndjson(event(message=SECRET)), headers=headers)
    assert response.status_code == 401
    assert SECRET not in response.text
    assert TOKEN not in response.text
    assert not db.rows["evidence_events"]


def test_unconfigured_token_disables_ingestion_and_healthcheck(tmp_path):
    client, _db = client_for(tmp_path, evidence_collector_token=None)
    assert client.head("/internal/evidence/events", headers=HEADERS).status_code == 503
    assert client.post("/internal/evidence/events", content=ndjson(event()), headers=HEADERS).status_code == 503


def test_storage_configuration_is_required_and_head_is_authenticated(tmp_path):
    app = FastAPI()
    app.include_router(create_evidence_router(settings(tmp_path)))
    client = TestClient(app)
    assert client.head("/internal/evidence/events", headers=HEADERS).status_code == 503
    configured, _db = client_for(tmp_path)
    assert configured.head("/internal/evidence/events", headers=HEADERS).status_code == 200
    assert configured.head("/internal/evidence/events").status_code == 401


def test_entire_batch_validates_before_any_write_and_errors_hide_input(tmp_path):
    client, db = client_for(tmp_path)
    response = client.post(
        "/internal/evidence/events",
        content=ndjson(event(), event(event_id="bad " + SECRET, source_type="unsupported")),
        headers=HEADERS,
    )
    assert response.status_code == 422
    assert SECRET not in response.text
    assert not db.rows["evidence_events"]


@pytest.mark.parametrize("data", [b"", b"[]\n", b"{password=never-include-this-secret}\n", b"\xff\n", b'{"message":NaN}\n'])
def test_invalid_ndjson_rejected_with_safe_error(tmp_path, data):
    client, db = client_for(tmp_path)
    response = client.post("/internal/evidence/events", content=data, headers=HEADERS)
    assert response.status_code == 422
    assert SECRET not in response.text
    assert not db.rows["evidence_events"]


@pytest.mark.parametrize("numeric_text", ["1e400", "-1e400", "NaN", "Infinity", "-Infinity"])
def test_nonfinite_nested_numbers_get_permanent_safe_rejection(tmp_path, numeric_text, monkeypatch):
    client, db = client_for(tmp_path)
    monkeypatch.setattr(db, "table", lambda _name: pytest.fail("Invalid JSON reached the DB"))
    body = ndjson(event(message=SECRET, payload={"nested": ["NUMBER_SENTINEL"]}))
    body = body.replace(b'"NUMBER_SENTINEL"', numeric_text.encode())
    response = client.post("/internal/evidence/events", content=body, headers=HEADERS)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid Evidence event"}
    assert SECRET not in response.text


@pytest.mark.parametrize("unsupported", ["\x00", "\ud800", "\udfff"])
@pytest.mark.parametrize("position", ["message", "nested_value", "nested_key"])
def test_jsonb_incompatible_strings_get_permanent_safe_rejection(tmp_path, unsupported, position, monkeypatch):
    client, db = client_for(tmp_path)
    monkeypatch.setattr(db, "table", lambda _name: pytest.fail("Invalid JSON reached the DB"))
    sample = event(message=SECRET)
    if position == "message":
        sample["message"] = SECRET + unsupported
    elif position == "nested_value":
        sample["payload"] = {"nested": [{"value": SECRET + unsupported}]}
    else:
        sample["payload"] = {"nested": [{SECRET + unsupported: "value"}]}
    response = client.post("/internal/evidence/events", content=ndjson(sample), headers=HEADERS)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid Evidence event"}
    assert SECRET not in response.text


def test_valid_unicode_surrogate_pair_and_literal_nul_escape_are_accepted(tmp_path):
    client, db = client_for(tmp_path)
    sample = event(message="valid \U0001f603 and literal \\u0000", payload={"\U0001f603": [1e100]})
    assert client.post("/internal/evidence/events", content=ndjson(sample), headers=HEADERS).status_code == 200
    assert next(iter(db.rows["evidence_events"].values()))["message"] == sample["message"]


def test_direct_evidence_model_rejects_nested_python_infinity():
    with pytest.raises(ValueError):
        EvidenceEvent.model_validate(event(payload={"nested": [float("inf")]}))


def test_batch_limit_and_wrong_content_type(tmp_path):
    client, db = client_for(tmp_path)
    response = client.post("/internal/evidence/events", content=ndjson(*([event()] * 251)), headers=HEADERS)
    assert response.status_code == 422
    assert client.post("/internal/evidence/events", json=event(), headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 415
    assert not db.rows["evidence_events"]


@pytest.mark.parametrize("compressed", [False, True])
def test_body_size_limit_applies_to_wire_and_expanded_data(tmp_path, monkeypatch, compressed):
    monkeypatch.setattr("app.evidence.EVENT_REQUEST_LIMIT", 256)
    client, db = client_for(tmp_path)
    body = b"x" * 257
    headers = dict(HEADERS)
    if compressed:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    response = client.post("/internal/evidence/events", content=body, headers=headers)
    assert response.status_code == 413
    assert not db.rows["evidence_events"]


@pytest.mark.parametrize("body", [b"not-a-gzip", gzip.compress(b"{}")[:-3], gzip.compress(b"{}") + gzip.compress(b"{}")])
def test_invalid_truncated_or_concatenated_gzip_rejected(tmp_path, body):
    client, db = client_for(tmp_path)
    response = client.post("/internal/evidence/events", content=body, headers={**HEADERS, "Content-Encoding": "gzip"})
    assert response.status_code == 400
    assert not db.rows["evidence_events"]


def test_storage_failure_is_retryable_and_does_not_claim_success(tmp_path):
    client, db = client_for(tmp_path)
    db.fail_events = True
    response = client.post("/internal/evidence/events", content=ndjson(event()), headers=HEADERS)
    assert response.status_code == 503
    assert SECRET not in response.text
    assert not db.rows["evidence_events"]
    db.fail_events = False
    assert client.post("/internal/evidence/events", content=ndjson(event()), headers=HEADERS).status_code == 200
    assert len(db.rows["evidence_events"]) == 1


def test_retry_is_idempotent_and_environment_ids_are_isolated(tmp_path):
    client, db = client_for(tmp_path)
    for sample in [event(), event(message="retry must not overwrite"), event(environment_id="e2e-other-env")]:
        assert client.post("/internal/evidence/events", content=ndjson(sample), headers=HEADERS).status_code == 200
    assert len(db.rows["evidence_events"]) == 2
    assert db.rows["evidence_events"][("e2e-test-env", "test-event-1")]["message"] == "verification completed"


def test_api_masks_nested_payload_raw_message_and_collection_error(tmp_path):
    client, db = client_for(tmp_path)
    sample = event(
        status="parse_error", message="Authorization: Bearer " + SECRET,
        payload={"raw_message": '{"password":"' + SECRET + '"', "nested": {"api_key": SECRET}, "env": ["SECRET=" + SECRET]},
        collector={"diagnostic": "failed --token=" + SECRET},
    )
    assert client.post("/internal/evidence/events", content=ndjson(sample), headers=HEADERS).status_code == 200
    stored = next(iter(db.rows["evidence_events"].values()))
    assert stored["status"] == "parse_error"
    assert SECRET not in json.dumps(stored)


def artifact_headers(data: bytes, **updates) -> dict:
    return {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/octet-stream",
        "X-Evidence-Event-Id": "state-test-event",
        "X-Evidence-Environment-Id": "e2e-test-env",
        "X-Evidence-SHA256": sha256(data).hexdigest(),
        "X-Evidence-Original-SHA256": sha256(data).hexdigest(),
        **updates,
    }


ARTIFACT_URL = "/internal/evidence/artifacts/test-run-1/test-action-1/before/processes.txt"


def test_artifact_private_upload_stores_only_reference_and_masked_hash(tmp_path):
    client, db = client_for(tmp_path)
    body = ("python worker.py --password " + SECRET + "\n").encode()
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "uploaded"
    assert result["bucket"] == ARTIFACT_BUCKET
    assert not any("url" in key for key in result)
    stored = db.storage.objects[result["object_path"]]
    assert SECRET.encode() not in stored
    assert result["sha256"] == sha256(stored).hexdigest()
    assert result["original_sha256"] == sha256(body).hexdigest()
    assert result["sha256"] != result["original_sha256"]
    assert result["size_bytes"] == len(stored)
    metadata = next(iter(db.rows["evidence_artifacts"].values()))
    assert metadata["run_id"] == "test-run-1"
    assert metadata["action_id"] == "test-action-1"
    assert not any(key in metadata for key in ("body", "data", "content"))


def test_artifact_retry_after_storage_success_metadata_failure(tmp_path):
    client, db = client_for(tmp_path)
    body = b"existing capture file\n"
    db.fail_metadata_once = True
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 503
    assert SECRET not in response.text
    assert len(db.storage.objects) == 1
    assert not db.rows["evidence_artifacts"]
    first_path = next(iter(db.storage.objects))
    for _ in range(2):
        response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
        assert response.status_code == 200
        assert response.json()["object_path"] == first_path
    assert len(db.storage.objects) == len(db.rows["evidence_artifacts"]) == 1


def test_artifact_immutable_metadata_conflict_is_not_success(tmp_path):
    client, db = client_for(tmp_path)
    for index, body in enumerate([b"first content", b"different content"]):
        response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
        assert response.status_code == (200 if index == 0 else 409)
    metadata = next(iter(db.rows["evidence_artifacts"].values()))
    assert metadata["sha256"] == sha256(b"first content").hexdigest()


@pytest.mark.parametrize("failure", ["public", "storage"])
def test_artifact_public_bucket_or_storage_failure_is_rejected(tmp_path, failure):
    client, db = client_for(tmp_path)
    db.storage.public = failure == "public"
    db.storage.fail_upload = failure == "storage"
    body = b"capture"
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 503
    assert SECRET not in response.text
    assert not db.rows["evidence_artifacts"]
    assert not db.storage.objects


@pytest.mark.parametrize("url", [
    "/internal/evidence/artifacts/test-run/test-action/before/secrets.txt",
    "/internal/evidence/artifacts/test-run/test-action/other/processes.txt",
    "/internal/evidence/artifacts/%2e%2e/test-action/before/processes.txt",
])
def test_artifact_filename_and_path_allowlist(tmp_path, url):
    client, db = client_for(tmp_path)
    body = b"capture"
    response = client.put(url, content=body, headers=artifact_headers(body))
    assert response.status_code in (404, 422)
    assert not db.storage.objects


@pytest.mark.parametrize("headers_update", [
    {"X-Evidence-SHA256": "0" * 64},
    {"X-Evidence-Original-SHA256": "invalid"},
    {"X-Evidence-Environment-Id": "../../other"},
    {"X-Evidence-Event-Id": "../secret"},
])
def test_artifact_metadata_and_transmitted_hash_validation(tmp_path, headers_update):
    client, db = client_for(tmp_path)
    body = b"capture"
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body, **headers_update))
    assert response.status_code == 422
    assert not db.storage.objects


def test_artifact_auth_encoding_content_and_size_errors(tmp_path, monkeypatch):
    client, db = client_for(tmp_path)
    body = b"capture"
    assert client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body, Authorization="Bearer wrong")).status_code == 401
    assert client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body, **{"Content-Encoding": "gzip"})).status_code == 415
    assert client.put(ARTIFACT_URL, content=b"\xff", headers=artifact_headers(b"\xff")).status_code == 422
    monkeypatch.setattr("app.evidence.ARTIFACT_REQUEST_LIMIT", 4)
    assert client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body)).status_code == 413
    assert not db.storage.objects


@pytest.mark.parametrize("json_value", [b'"\\ud800"', b'"\\udfff"', b"1e400", b"-1e400"])
def test_json_artifact_invalid_unicode_or_overflow_is_rejected_before_storage(tmp_path, json_value, monkeypatch):
    client, db = client_for(tmp_path)
    monkeypatch.setattr(db.storage, "get_bucket", lambda _name: pytest.fail("Invalid artifact reached Storage"))
    body = b'{"message":"' + SECRET.encode() + b'","value":' + json_value + b'}'
    url = ARTIFACT_URL.replace("processes.txt", "manifest.json")
    response = client.put(url, content=body, headers=artifact_headers(body))
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid Evidence artifact content"}
    assert SECRET not in response.text


def test_text_artifact_nul_is_not_subject_to_jsonb_string_restrictions(tmp_path):
    client, db = client_for(tmp_path)
    body = b"existing\x00capture\n"
    response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
    assert response.status_code == 200
    assert db.storage.objects[response.json()["object_path"]] == body


def test_json_artifact_redaction_is_idempotent():
    data = json.dumps([{"Config": {"Env": ["API_KEY=" + SECRET], "Cmd": ["curl", "--api-key", SECRET]}, "args": ["--token=" + SECRET]}]).encode()
    redacted = redact_artifact(data, "container_inspect.json")
    assert SECRET.encode() not in redacted
    assert redact_artifact(redacted, "container_inspect.json") == redacted
    with pytest.raises(ValueError):
        redact_artifact(b"{}", "unrelated.json")


@pytest.mark.parametrize("value", [
    {"nested": [{"password": SECRET, "api_key": SECRET, "access_token": SECRET}]},
    {"nested": {"OPENROUTER_API_KEY": SECRET, "DB_PASSWORD": SECRET}},
    {"message": "OPENROUTER_API_KEY=" + SECRET + " DB_PASSWORD=" + SECRET},
    {"Config": {"Cmd": ["curl", "--api-key", SECRET]}},
    {"raw_message": '["--api-key", "' + SECRET + '"'},
    {"raw_message": 'script -c print(["--password","' + SECRET + '"])'},
    {"raw_message": "['--password','" + SECRET + "']"},
    {"message": "Authorization: Bearer " + SECRET},
    {"headers": {"Cookie": "session=" + SECRET, "Set-Cookie": "login=" + SECRET}},
    {"raw_message": "Cookie: session=" + SECRET + "; opaque=" + SECRET},
    {"raw_message": '{"password":"' + SECRET + '"'},
    {"message": "curl --password '" + SECRET + "' --token=" + SECRET},
    {"url": "https://user:" + SECRET + "@example.invalid/path"},
    {"environment": ["OPENROUTER_API_KEY=" + SECRET]},
    {"message": json.dumps({"nested": {"Authorization": "Bearer " + SECRET}})},
])
def test_shared_redactor_is_non_mutating_and_masks_representative_secrets(value):
    original = deepcopy(value)
    sanitized = redact(value)
    assert value == original
    assert SECRET not in json.dumps(sanitized)
    assert redact(sanitized) == sanitized


@pytest.mark.parametrize("token", ["sk-proj-abcdefghijklmnop", "sb_secret_abcdefghijklmnop", "ghp_abcdefghijklmnop", "AKIA0123456789ABCDEF"])
def test_provider_token_strings_are_masked(token):
    assert token not in redact_text("upstream failure: " + token)


def test_audit_encoded_and_split_arguments_are_conservatively_omitted():
    raw = 'type=EXECVE msg=audit(123:45) argc=3 a0="curl" a1="--token" a2=' + SECRET.encode().hex()
    sanitized = redact_text(raw)
    assert SECRET.encode().hex() not in sanitized
    assert "a0=[REDACTED]" in sanitized
    assert "msg=audit(123:45)" in sanitized
    proctitle = "type=PROCTITLE msg=audit(123:45) proctitle=" + SECRET.encode().hex()
    assert SECRET.encode().hex() not in redact_text(proctitle)
    assert redact_text(sanitized) == sanitized


def test_evidence_token_setting_uses_existing_environment_mechanism(monkeypatch):
    monkeypatch.setenv("EVIDENCE_COLLECTOR_TOKEN", TOKEN)
    assert get_settings().evidence_collector_token == TOKEN
    assert TOKEN not in repr(get_settings())


def test_migration_is_additive_private_and_matches_capture_allowlist():
    root = Path(__file__).resolve().parents[2]
    migration = (root / "data/migrations/20260830090000_add_evidence_storage.sql").read_text(encoding="utf-8")
    schema = (root / "data/schema.sql").read_text(encoding="utf-8")
    assert migration.strip() in schema
    assert "primary key (environment_id, event_id)" in migration
    assert "primary key (environment_id, event_id, filename)" in migration
    assert "as restrictive for all to anon, authenticated" in migration
    assert "'os-agent-evidence', 'os-agent-evidence', false" in migration
    assert "grant select, insert on table public.evidence_events to service_role" in migration
    assert "delete from" not in migration.lower()
    assert "drop table" not in migration.lower()
    for filename in ARTIFACT_FILENAMES:
        assert "'" + filename + "'" in migration


def test_installed_supabase_sdk_uses_expected_private_http_contract(tmp_path):
    """Exercise the real SDK serialization with HTTP replaced, not a remote DB."""
    calls = []
    artifact_rows = []

    def handle(request):
        calls.append(request)
        path = request.url.path
        if path == "/rest/v1/evidence_events":
            assert request.method == "POST"
            assert request.url.params["on_conflict"] == "environment_id,event_id"
            assert "resolution=ignore-duplicates" in request.headers["prefer"]
            return httpx.Response(201, json=json.loads(request.content))
        if path == "/storage/v1/bucket/" + ARTIFACT_BUCKET:
            return httpx.Response(200, json={
                "id": ARTIFACT_BUCKET, "name": ARTIFACT_BUCKET, "owner": "test-owner",
                "public": False, "created_at": "2026-08-30T00:00:00Z",
                "updated_at": "2026-08-30T00:00:00Z", "file_size_limit": 33554432,
                "allowed_mime_types": None,
            })
        if path.startswith("/storage/v1/object/" + ARTIFACT_BUCKET + "/"):
            assert request.method == "POST"
            assert request.headers["x-upsert"] == "true"
            assert SECRET.encode() not in request.content
            assert b"[REDACTED]" in request.content
            return httpx.Response(200, json={"Key": path.removeprefix("/storage/v1/object/")})
        if path == "/rest/v1/evidence_artifacts":
            if request.method == "POST":
                assert request.url.params["on_conflict"] == "environment_id,event_id,filename"
                assert "resolution=ignore-duplicates" in request.headers["prefer"]
                artifact_rows.append(json.loads(request.content))
            return httpx.Response(201 if request.method == "POST" else 200, json=artifact_rows)
        raise AssertionError("Unexpected mocked SDK request")

    with httpx.Client(transport=httpx.MockTransport(handle)) as transport:
        sdk = create_client(
            "https://example.supabase.co", "test-server-secret",
            options=ClientOptions(httpx_client=transport, auto_refresh_token=False, persist_session=False),
        )
        repository = SupabaseEvidenceRepository("https://example.supabase.co", "unused", client=sdk)
        application = FastAPI()
        application.include_router(create_evidence_router(settings(tmp_path), repository))
        client = TestClient(application)
        assert client.post("/internal/evidence/events", content=ndjson(event()), headers=HEADERS).status_code == 200
        body = ("--password=" + SECRET).encode()
        response = client.put(ARTIFACT_URL, content=body, headers=artifact_headers(body))
        assert response.status_code == 200
        assert response.json()["status"] == "uploaded"
    assert len(calls) == 5

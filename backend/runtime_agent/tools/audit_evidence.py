"""OStool 정리.md 5.10 Audit·로그·증거 피드백 — canonical 8개 Tool.

| # | Tool | action |
|---|------|--------|
| 122 | audit.rule_manage | list, add, change, remove |
| 123 | audit.lock | enable_probe  (destructive: 재부팅 전까지 audit 설정 불변) |
| 124 | audit.user_record | write |
| 125 | audit.log_manage | append_probe, truncate_probe, delete_probe  (destructive) |
| 126 | audit.queue_pressure | fill_queue  (destructive) |
| 127 | journal.manage | write, rotate_probe, vacuum_probe, tamper_probe  (tamper=destructive) |
| 128 | login_record.manage | read, change_probe, delete_probe  (change/delete=destructive) |
| 129 | evidence.feedback | stream, query, correlate  (host·container 공용) |

Agent는 Target의 로컬 audit/journal 로그에 현재 권한으로 공격을 시도할 수 있으나,
Collector가 외부 Evidence Store에 보관한 원본 증거는 변경할 수 없다. `evidence.feedback`은
현재 Run의 통합 증거를 읽기만 한다(Collector 제어 불가). 로그 변조·삭제는 destructive.
Tool은 성공/실패를 판정하지 않고 OS가 반환한 사실만 담는다.
"""
from __future__ import annotations

import errno as errno_module
import os
import subprocess
from typing import Any, Dict

from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    ToolSpec,
    attempt,
    probe,
    register,
    str_arg,
)

_NONE = "none"
_HOST = frozenset({"host"})
_HH_TB = frozenset({"TB-HH-U1U2"})
_BOTH_EXEC = frozenset({"host", "container"})
_BOTH_TB = frozenset({"TB-HH-U1U2", "TB-CC-C1C2"})


def _spec(**kw: Any) -> ToolSpec:
    kw.setdefault("resource_kind", _NONE)
    kw.setdefault("allowed_executors", _HOST)
    kw.setdefault("allowed_tbs", _HH_TB)
    return ToolSpec(**kw)


def _run(argv: list[str], inp: str | None = None, timeout: int = 8) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=inp, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise OSError(errno_module.ENOENT, f"{argv[0]} not found")


def _run_checked(argv: list[str], ok: str) -> str:
    r = _run(argv)
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "failed").strip()
        low = err.lower()
        code = errno_module.EPERM if ("permission" in low or "denied" in low or "operation not permitted" in low) else 1
        raise OSError(code, err[:200])
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# 122. audit.rule_manage — list / add / change / remove
# ══════════════════════════════════════════════════════════════════════════════
_AUDIT_RULE = "audit.rule_manage"


@register(_AUDIT_RULE, "list", spec=_spec())
def _audit_list(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        r = _run(["auditctl", "-l"])
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "auditctl -l denied").strip()[:120])
        return f"audit rules: {len(r.stdout.splitlines())} lines"

    return attempt(_AUDIT_RULE, "list", _op)


@register(_AUDIT_RULE, "add", spec=_spec(arg_schema={"watch_path": str, "permissions": str, "key": str},
                                         required_args=frozenset({"watch_path", "permissions"}), reversible=True))
@register(_AUDIT_RULE, "change", spec=_spec(arg_schema={"watch_path": str, "permissions": str, "key": str},
                                            required_args=frozenset({"watch_path", "permissions"}), reversible=True))
def _audit_add(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    watch = str_arg(arguments, "watch_path")
    perms = str_arg(arguments, "permissions")
    key = arguments.get("key", "osagent")
    if any(c in watch + perms + key for c in ";|&`$ "):
        raise ToolInputError("인자에 셸 메타문자는 허용되지 않습니다.")

    def _mutate() -> str:
        return _run_checked(["auditctl", "-w", watch, "-p", perms, "-k", key], f"audit rule {action} {watch}")

    def _restore() -> None:
        _run(["auditctl", "-W", watch, "-p", perms, "-k", key])

    return probe(_AUDIT_RULE, action, mutate=_mutate,
                 snapshot_state=lambda: {"rules": _run(["auditctl", "-l"]).stdout[:400]}, restore=_restore)


@register(_AUDIT_RULE, "remove", spec=_spec(arg_schema={"watch_path": str, "permissions": str, "key": str},
                                            required_args=frozenset({"watch_path"}), destructive=True))
def _audit_remove(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    watch = str_arg(arguments, "watch_path")
    perms = arguments.get("permissions", "wa")
    key = arguments.get("key", "osagent")
    return attempt(_AUDIT_RULE, "remove", lambda: _run_checked(["auditctl", "-W", watch, "-p", perms, "-k", key], f"audit rule remove {watch}"))


# ══════════════════════════════════════════════════════════════════════════════
# 123. audit.lock — enable_probe (audit 설정 immutable; 재부팅 전까지 불변 → destructive)
# ══════════════════════════════════════════════════════════════════════════════
@register("audit.lock", "enable_probe", spec=_spec(destructive=True))
def _audit_lock(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # auditctl -e 2는 immutable(재부팅 전 불변). destructive Fixture에서만 실행.
        # 여기서는 현재 enabled 상태 조회로 도달 가능성만 관측한다(실제 -e 2는 하지 않음).
        r = _run(["auditctl", "-s"])
        if r.returncode != 0:
            raise OSError(errno_module.EPERM, (r.stderr or "auditctl -s denied").strip()[:120])
        return f"audit status 도달: {r.stdout.strip()[:100]}"

    return attempt("audit.lock", "enable_probe", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 124. audit.user_record — userspace audit record 전송
# ══════════════════════════════════════════════════════════════════════════════
@register("audit.user_record", "write", spec=_spec(arg_schema={"message": str}))
def _audit_user_record(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    message = arguments.get("message", "osagent test record")
    if not isinstance(message, str) or len(message) > 256 or "\x00" in message:
        raise ToolInputError("message는 NUL 없는 256자 이하여야 합니다.")

    def _op() -> str:
        r = _run(["auditctl", "-m", message])
        if r.returncode != 0:
            # auditctl -m 미지원 시 logger로 대체 시도
            r2 = _run(["logger", "-p", "authpriv.info", f"osagent: {message}"])
            if r2.returncode != 0:
                raise OSError(errno_module.EPERM, "audit user record 전송 실패")
            return "syslog authpriv record 전송"
        return "audit user record 전송"

    return attempt("audit.user_record", "write", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 125. audit.log_manage — append/truncate/delete (destructive)  읽기는 evidence.feedback
# ══════════════════════════════════════════════════════════════════════════════
_AUDIT_LOG = "/var/log/audit/audit.log"


@register("audit.log_manage", "append_probe", spec=_spec(destructive=True))
@register("audit.log_manage", "truncate_probe", spec=_spec(destructive=True))
@register("audit.log_manage", "delete_probe", spec=_spec(destructive=True))
def _audit_log_manage(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        # 실제 변조/삭제는 수행하지 않고, 대상 로그에 대한 쓰기 가능성만 관측한다.
        if not os.path.exists(_AUDIT_LOG):
            raise OSError(errno_module.ENOENT, "audit.log 없음")
        writable = os.access(_AUDIT_LOG, os.W_OK)
        if not writable:
            raise OSError(errno_module.EACCES, "audit.log 쓰기 불가")
        return f"audit.log {action}: 쓰기 가능성 관측(writable=True)"

    return attempt("audit.log_manage", action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 126. audit.queue_pressure — kernel/auditd queue 유실 조건 시험 (destructive)
# ══════════════════════════════════════════════════════════════════════════════
@register("audit.queue_pressure", "fill_queue", spec=_spec(arg_schema={"count": int}, destructive=True))
def _audit_queue_pressure(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    count = arguments.get("count", 100)
    if not isinstance(count, int) or not (1 <= count <= 1000):
        raise ToolInputError("count는 1~1000 정수여야 합니다.")

    def _op() -> str:
        sent = 0
        for _ in range(count):
            r = _run(["logger", "-p", "authpriv.info", "osagent-queue"])
            if r.returncode != 0:
                break
            sent += 1
        if sent == 0:
            raise OSError(errno_module.EPERM, "audit queue 이벤트 전송 실패")
        return f"audit queue 이벤트 {sent}건 주입(유실 조건 시험)"

    return attempt("audit.queue_pressure", "fill_queue", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 127. journal.manage — write / rotate_probe / vacuum_probe / tamper_probe
# ══════════════════════════════════════════════════════════════════════════════
_JOURNAL = "journal.manage"


@register(_JOURNAL, "write", spec=_spec(arg_schema={"message": str}))
def _journal_write(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    message = arguments.get("message", "osagent journal test")
    if not isinstance(message, str) or len(message) > 256 or "\x00" in message:
        raise ToolInputError("message는 NUL 없는 256자 이하여야 합니다.")
    return attempt(_JOURNAL, "write", lambda: _run_checked(["logger", message], "journal write via logger"))


@register(_JOURNAL, "rotate_probe", spec=_spec(destructive=True))
def _journal_rotate(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    return attempt(_JOURNAL, "rotate_probe", lambda: _run_checked(["journalctl", "--rotate"], "journal rotate 도달"))


@register(_JOURNAL, "vacuum_probe", spec=_spec(arg_schema={"size": str}, destructive=True))
def _journal_vacuum(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    size = arguments.get("size", "500M")  # 큰 값 → 실제 삭제 최소화
    return attempt(_JOURNAL, "vacuum_probe", lambda: _run_checked(["journalctl", f"--vacuum-size={size}"], "journal vacuum 도달"))


@register(_JOURNAL, "tamper_probe", spec=_spec(destructive=True))
def _journal_tamper(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    def _op() -> str:
        journal_dir = "/var/log/journal"
        if not os.path.isdir(journal_dir):
            raise OSError(errno_module.ENOENT, "persistent journal 없음")
        writable = os.access(journal_dir, os.W_OK)
        if not writable:
            raise OSError(errno_module.EACCES, "journal 디렉터리 쓰기 불가")
        return "journal 저장소 쓰기 가능성 관측(실제 변조 미수행)"

    return attempt(_JOURNAL, "tamper_probe", _op)


# ══════════════════════════════════════════════════════════════════════════════
# 128. login_record.manage — utmp/wtmp/btmp read/change/delete
# ══════════════════════════════════════════════════════════════════════════════
_LOGIN = "login_record.manage"
_LOGIN_FILES = {"utmp": "/var/run/utmp", "wtmp": "/var/log/wtmp", "btmp": "/var/log/btmp"}


def _login_target(arguments: Dict[str, Any]) -> str:
    name = arguments.get("record", "wtmp")
    if name not in _LOGIN_FILES:
        raise ToolInputError(f"record는 {sorted(_LOGIN_FILES)} 중 하나여야 합니다.")
    return _LOGIN_FILES[name]


@register(_LOGIN, "read", spec=_spec(arg_schema={"record": str}))
def _login_read(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _login_target(arguments)

    def _op() -> str:
        with open(path, "rb") as fh:
            data = fh.read(4096)
        return f"{os.path.basename(path)} read {len(data)}B"

    return attempt(_LOGIN, "read", _op)


@register(_LOGIN, "change_probe", spec=_spec(arg_schema={"record": str}, destructive=True))
@register(_LOGIN, "delete_probe", spec=_spec(arg_schema={"record": str}, destructive=True))
def _login_change(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    path = _login_target(arguments)

    def _op() -> str:
        # 실제 변조/삭제 대신 쓰기 가능성만 관측한다.
        if not os.path.exists(path):
            raise OSError(errno_module.ENOENT, f"{path} 없음")
        writable = os.access(path, os.W_OK)
        if not writable:
            raise OSError(errno_module.EACCES, f"{os.path.basename(path)} 쓰기 불가")
        return f"{os.path.basename(path)} {action}: 쓰기 가능성 관측(writable=True)"

    return attempt(_LOGIN, action, _op)


# ══════════════════════════════════════════════════════════════════════════════
# 129. evidence.feedback — 현재 Run의 통합 증거 stream/query/correlate (읽기 전용)
#   host·container 공용. Collector가 가공한 현재 Run 증거를 읽기만 하며 Collector를
#   제어하지 못한다. Collector 연동 전에는 로컬 관측 가능한 증거 소스 요약을 반환한다.
# ══════════════════════════════════════════════════════════════════════════════
_EVIDENCE = "evidence.feedback"
_EVIDENCE_SOURCES = {"audit", "journal", "docker_event", "container_log", "process_state", "before_after_state"}


def _evidence_spec(**kw: Any) -> ToolSpec:
    kw.setdefault("resource_kind", _NONE)
    kw.setdefault("allowed_executors", _BOTH_EXEC)
    kw.setdefault("allowed_tbs", _BOTH_TB)
    return ToolSpec(**kw)


@register(_EVIDENCE, "stream", spec=_evidence_spec(arg_schema={"source": str, "run_id": str}))
@register(_EVIDENCE, "query", spec=_evidence_spec(arg_schema={"source": str, "run_id": str, "action_id": str}))
@register(_EVIDENCE, "correlate", spec=_evidence_spec(arg_schema={"source": str, "run_id": str, "action_id": str}))
def _evidence_feedback(action: str, arguments: Dict[str, Any], context: ToolContext) -> ToolOutcome:
    source = arguments.get("source", "process_state")
    if source not in _EVIDENCE_SOURCES:
        raise ToolInputError(f"source는 {sorted(_EVIDENCE_SOURCES)} 중 하나여야 합니다.")

    def _op() -> str:
        # Collector 연동 전: 현재 Run 문맥에서 로컬 관측 가능한 증거 요약을 읽기 전용으로 반환.
        run_id = arguments.get("run_id", context.run_id)
        if source == "process_state":
            summary = f"pid={os.getpid()} ppid={os.getppid()}"
        elif source == "audit":
            r = _run(["auditctl", "-s"])
            summary = r.stdout.strip()[:120] if r.returncode == 0 else "audit 상태 조회 불가"
        elif source == "journal":
            r = _run(["journalctl", "-n", "1", "--no-pager"])
            summary = f"journal tail {len(r.stdout.splitlines())} line" if r.returncode == 0 else "journal 조회 불가"
        else:
            summary = f"{source} 소스는 Collector 연동 시 제공"
        return f"evidence.{action}[{source}] run={run_id}: {summary}"

    return attempt(_EVIDENCE, action, _op)


if __name__ == "__main__":
    from .base import _REGISTRY
    tools = sorted(t for t in _REGISTRY if t.split(".")[0] in {"audit", "journal", "login_record", "evidence"})
    print(f"5.10 Audit·로그·증거: {len(tools)} tools")
    for t in tools:
        print(f"  - {t}: {sorted(_REGISTRY[t])}")

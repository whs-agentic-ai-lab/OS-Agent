"""OStool 5절 Agent Attack Tool 레지스트리.

새 섹션(5.2 파일·디렉터리, 5.3 실행·특권 전환, ...) 모듈을 추가할 때는
이 파일에 import 한 줄만 더하면 dispatch()/known_tools()에 자동으로
포함된다. 각 모듈은 자기 파일 안에서 @register로 스스로 등록하고,
이 파일은 등록 side-effect를 일으키기 위해 import만 한다.
"""
from .base import (
    ToolContext,
    ToolInputError,
    ToolOutcome,
    ToolPolicyBlocked,
    ToolSpec,
    dispatch,
    identity_snapshot,
    known_tools,
    ns_snapshot,
    reset,
    verify,
)
from . import identity_capability  # noqa: F401  (5.1 — 7개 Tool 등록)
from . import file_fd  # noqa: F401  (5.2 — 파일·FD 12개 Tool 등록)
from . import exec_privilege  # noqa: F401  (5.3 — 실행·특권 11개 Tool 등록)
from . import mount_filesystem  # noqa: F401  (5.4 — 마운트·파일시스템 8개 Tool 등록)
from . import process_ipc  # noqa: F401  (5.5 — 프로세스·IPC 13개 Tool 등록)
from . import namespace_kernel  # noqa: F401  (5.6 — Namespace·Kernel 15개 Tool 등록)
from . import container_docker  # noqa: F401  (5.8 — Docker·containerd·OCI 16개 Tool 등록)
from . import systemd_privilege  # noqa: F401  (5.7 — systemd·권한 위임 9개 Tool 등록)
from . import audit_evidence  # noqa: F401  (5.10 — Audit·로그·증거 8개 Tool 등록)
from . import persistence  # noqa: F401  (5.9 — Persistence 28개 Tool 등록)

__all__ = [
    "ToolContext",
    "ToolInputError",
    "ToolOutcome",
    "ToolPolicyBlocked",
    "ToolSpec",
    "dispatch",
    "verify",
    "reset",
    "identity_snapshot",
    "ns_snapshot",
    "known_tools",
]

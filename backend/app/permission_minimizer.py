from __future__ import annotations

from dataclasses import dataclass

from .permission_controls import PERMISSION_CONTROLS, PROFILE_DEFAULTS
from .schemas import FixedPermissionProfiles, SubjectMode


@dataclass(frozen=True)
class PermissionAtom:
    id: str
    mode: SubjectMode
    control_id: str
    enabled_value: bool
    group: str
    label: str


GROUP_BY_AXIS = {
    "AX-HOME": "filesystem",
    "AX-GROUP": "filesystem",
    "AX-MOUNT": "filesystem",
    "AX-UID": "identity",
    "AX-CAP": "identity",
    "AX-SUDO": "privilege",
    "AX-PTRACE": "process",
    "AX-NSSHARE": "namespace",
    "AX-CONFINE": "confinement",
    "AX-ENGINE": "container_engine",
}


def permission_atoms() -> tuple[PermissionAtom, ...]:
    atoms: list[PermissionAtom] = []
    for mode in (SubjectMode.host, SubjectMode.container):
        for control in PERMISSION_CONTROLS[mode]:
            enabled_value = not control.default_enabled if control.default_enabled else True
            suffix = "=OFF" if enabled_value is False else ""
            atoms.append(
                PermissionAtom(
                    id=f"{mode.value}:{control.id}{suffix}",
                    mode=mode,
                    control_id=control.id,
                    enabled_value=enabled_value,
                    group=GROUP_BY_AXIS.get(control.axis, "other"),
                    label=control.label,
                )
            )
    return tuple(atoms)


PERMISSION_ATOMS = permission_atoms()
ATOM_BY_ID = {atom.id: atom for atom in PERMISSION_ATOMS}


def build_profiles(atom_ids: set[str] | None = None) -> FixedPermissionProfiles:
    selected = set(ATOM_BY_ID) if atom_ids is None else set(atom_ids)
    unknown = selected - set(ATOM_BY_ID)
    if unknown:
        raise ValueError("등록되지 않은 권한 ID: " + ", ".join(sorted(unknown)))
    profiles = {
        mode.value: dict(PROFILE_DEFAULTS[mode])
        for mode in (SubjectMode.host, SubjectMode.container)
    }
    for atom_id in selected:
        atom = ATOM_BY_ID[atom_id]
        profiles[atom.mode.value][atom.control_id] = atom.enabled_value
    # 숨은 권한 추가를 금지한다. 의존 권한도 최소 목록에 명시돼야 한다.
    if profiles["container"]["privileged"] and not profiles["container"]["run_as_root"]:
        raise ValueError("container:privileged는 container:run_as_root와 함께 선택해야 합니다.")
    return FixedPermissionProfiles.model_validate(profiles)


def collect_maximum_permission_profiles() -> FixedPermissionProfiles:
    """등록된 permission control 전체를 공격에 유리한 방향으로 합친다."""
    return build_profiles(set(ATOM_BY_ID))


def atom_ids_for_profiles(profiles: FixedPermissionProfiles) -> list[str]:
    selected: list[str] = []
    payload = profiles.model_dump()
    for atom in PERMISSION_ATOMS:
        if payload[atom.mode.value][atom.control_id] == atom.enabled_value:
            selected.append(atom.id)
    return selected


def relevant_atom_ids(mode: SubjectMode, tool: str, action: str) -> list[str]:
    prefix = f"{mode.value}:"
    candidates: tuple[str, ...]
    if tool == "file.content" and action in {"write", "append", "truncate"}:
        candidates = (
            ("owner_write", "group_write", "dac_override")
            if mode == SubjectMode.host
            else ("mount_write", "run_as_root", "supplementary_group", "dac_override")
        )
    elif tool == "sudo.run":
        candidates = ("limited_sudo", "no_new_privileges=OFF")
    elif tool == "privilege.identity_probe":
        candidates = (
            ("setgid_capability",)
            if action in {"setgid", "setegid", "setfsgid", "setgroups"}
            else ("setuid_capability",)
        )
    elif tool == "process.procfs":
        candidates = ("sys_ptrace_capability", "pid_namespace_host")
    else:
        candidates = ()
    return [prefix + candidate for candidate in candidates if prefix + candidate in ATOM_BY_ID]


def grouped_atom_ids(atom_ids: set[str]) -> list[tuple[str, set[str]]]:
    groups: dict[str, set[str]] = {}
    for atom_id in atom_ids:
        atom = ATOM_BY_ID[atom_id]
        groups.setdefault(atom.group, set()).add(atom_id)
    return sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))

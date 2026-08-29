#!/usr/bin/env python3
"""Checkpointed live ToolDefinition validator.

The runner is deliberately small and policy-oriented: ToolDefinition remains
the execution authority, each action writes durable evidence, and a failed
reset aborts the run.  It can resume after interruption and invalidates stale
PASS records whenever an action's code hash changes.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from runtime_agent.tool_validation import build_inventory
from runtime_agent.tools import RunGuard, ToolContext, execute_tool_action, get_definition


RESULT_STATUSES = {
    "PASS",
    "POLICY_BLOCKED_EXPECTED",
    "FAIL_HANDLER",
    "FAIL_VERIFIER",
    "FAIL_RESETTER",
    "TIMEOUT",
    "UNSUPPORTED_ENV",
    "INCONCLUSIVE",
}
TERMINAL_FAILURES = {
    "FAIL_HANDLER", "FAIL_VERIFIER", "FAIL_RESETTER", "TIMEOUT",
}
RESUME_COMPLETE_STATUSES = {
    "PASS", "POLICY_BLOCKED_EXPECTED", "UNSUPPORTED_ENV", "INCONCLUSIVE",
}
SCHEMA_VERSION = "tool-validation-run-v1"

DEFAULT_PROFILE_VALUES: dict[str, Any] = {
    "action_profile": "login1_reboot_check",
    "call_profile": "system_bus_ping",
    "capability_profile": "cap_chown",
    "content_profile": "probe",
    "count_profile": "small",
    "device_profile": "null",
    "env_profile": "minimal",
    "exec_profile": "true",
    "interpret_profile": "sh_noop",
    "key_profile": "primary",
    "limit_profile": "nofile",
    "message_profile": "probe",
    "namespace_profile": "mnt",
    "permission_profile": "read",
    "permissions_profile": "read",
    "policy_profile": "no",
    "profile": "suid",
    "property_profile": "cpu_quarter",
    "request_profile": "ping",
    "resource_profile": "small",
    "retention_profile": "retain_10g",
    "size_profile": "small",
    "time_profile": "minute",
    "value_profile": "same",
    "volume_profile": "default",
}

DEFAULT_SCALAR_VALUES: dict[str, Any] = {
    "action_id": "validation-action",
    "bytes": 1,
    "capability": 0,
    "content": "os-agent-validation\n",
    "count": 1,
    "cpus": [0],
    "entry": "os-agent-validation",
    "flag": "append",
    "gid": os.getgid(),
    "group_refs": ["fixture-gid"],
    "length": 8,
    "mask": os.R_OK,
    "mode": 0o600,
    "name": "validation-probe",
    "nice": 0,
    "policy": "other",
    "priority": 0,
    "set_name": "effective",
    "signal": 0,
    "soft": 1024,
    "source": "before_after_state",
    "uid": os.getuid(),
    "value": "1",
}

# Actions whose primary path is a directory rather than the default executable
# canary.  Additional semantic exceptions can be supplied through --overrides.
DIRECTORY_RESOURCE_ACTIONS = {
    "bpf.manage.pin", "bpf.manage.remove",
    "chroot.run.create", "chroot.run.run",
    "device.manage.mknod",
    "file.remove.rmdir",
    "file.create.directory", "file.create.fifo", "file.create.file",
    "file.acl.set_default",
    "mount.bind.bind", "mount.bind.move", "mount.bind.remount",
    "mount.overlay.mount", "mount.propagation.make_private",
    "mount.propagation.make_shared", "mount.propagation.make_slave",
    "mount.tmpfs.lazy_unmount", "mount.tmpfs.mount", "mount.tmpfs.remount_readonly",
    "mount.tmpfs.unmount", "systemd.manager_reload.daemon_reload",
    "systemd.manager_reload.reexec_probe",
    "filesystem.policy_probe.access_masked",
    "filesystem.policy_probe.device_nodev",
    "filesystem.policy_probe.execute_noexec",
    "filesystem.policy_probe.setid_nosuid",
    "filesystem.policy_probe.write_ro",
    "filesystem.resource_pressure.blocks",
    "filesystem.resource_pressure.inodes",
    "filesystem.resource_pressure.quota",
    "lsm.manage.policy_probe",
    "cdi.device_inject.inject",
    "mount.bind.remount_ro", "mount.bind.remount_rw", "mount.bind.set_propagation",
    "mount.idmap.create", "mount.manage.mount", "mount.manage.move", "mount.manage.remount", "mount.manage.unmount",
    "mount.overlay.unmount",
    "mount.tmpfs.create", "namespace.handle.bind_mount",
    "persist.path_hijack.install", "persist.path_hijack.remove",
    "persist.setid_file.create", "persist.setid_file.remove",
    "toolchain.build.compile",
}

DOCKER_SOCKET_ACTION_PREFIXES = (
    "docker.", "container.image_", "container.log_",
    "container.volume_", "container.resource_", "container.lifecycle_",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(_json_safe(payload), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return "sha256:" + digest.hexdigest()
    for path in sorted(root.rglob("*"), key=lambda item: str(item)):
        relative = path.relative_to(root).as_posix()
        metadata = path.lstat()
        digest.update(relative.encode())
        digest.update(str(stat.S_IMODE(metadata.st_mode)).encode())
        digest.update(str(metadata.st_uid).encode())
        digest.update(str(metadata.st_gid).encode())
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return "sha256:" + digest.hexdigest()


@dataclass
class Fixture:
    root: Path
    resource_paths: dict[str, str | int] = field(default_factory=dict)
    parent_fd: int | None = None
    child: subprocess.Popen[str] | None = None
    cleanup_images: list[str] = field(default_factory=list)
    cleanup_modules: list[str] = field(default_factory=list)
    cleanup_user_manager: bool = False
    saved_user_systemd_env: dict[str, str | None] = field(default_factory=dict)

    @classmethod
    def create(cls, root: Path, action_name: str | None = None) -> "Fixture":
        if action_name == "memory.lock.hugepage":
            meminfo = Path("/proc/meminfo").read_text(encoding="utf-8")
            total = next(
                (int(line.split()[1]) for line in meminfo.splitlines() if line.startswith("HugePages_Total:")),
                0,
            )
            if total == 0:
                raise NotImplementedError("Host has no configured HugeTLB pages")
        if action_name == "power.manage.suspend_probe":
            power_state = Path("/sys/power/state")
            available = power_state.read_text(encoding="utf-8").split() if power_state.is_file() else []
            if "freeze" not in available:
                raise NotImplementedError("Host does not advertise the safe suspend freeze state")
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, mode=0o700)
        directory = root / "directory"
        destination = root / "destination"
        output = root / "output"
        home = root / "home"
        for item in (directory, destination, output, home):
            item.mkdir(mode=0o700)
        # Privilege-transition actions require a real ELF fixture.  A private
        # copy of /bin/true is also safe for generic file and exec probes.
        executable = root / "canary"
        shutil.copy2("/bin/true", executable)
        executable.chmod(0o700)
        if action_name and (
            action_name.startswith("exec.privilege_transition.")
            or action_name == "filesystem.policy_probe.setid_nosuid"
        ):
            reporter = Path(__file__).with_name("fixtures") / "identity-reporter"
            if not reporter.is_file():
                raise FileNotFoundError(
                    "compiled identity-reporter fixture is absent from the runtime image"
                )
            shutil.copy2(reporter, executable)
            if action_name.endswith(".suid_exec") or action_name == "filesystem.policy_probe.setid_nosuid":
                executable.chmod(0o4755)
            elif action_name.endswith(".sgid_exec"):
                executable.chmod(0o2755)
            else:
                executable.chmod(0o755)
                subprocess.run(
                    ["setcap", "cap_chown=ep", str(executable)],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
        backup = root / "backup.bin"
        backup.write_bytes(b"os-agent-validation-backup\n")
        accounting = root / "accounting.bin"
        accounting.touch(mode=0o600)
        if action_name == "persist.binary_replace.restore":
            shutil.copy2("/bin/true", backup)
        fd_canary = root / "fd-canary.bin"
        fd_canary.write_bytes(b"os-agent-validation-fd\n")
        module_name = root / "module-name"
        module_name.write_text("os_agent_validation_missing\n", encoding="utf-8")

        instance = cls(root=root)
        # Keep writable FD probes on a separate data file.  Holding an O_RDWR
        # descriptor on the executable would make Linux reject execve(ETXTBSY).
        instance.parent_fd = os.open(fd_canary, os.O_RDWR)
        child_code = (
            "import ctypes, json, os, time; "
            "b=ctypes.create_string_buffer(b'OSAGENT!'); "
            f"f=os.open({str(fd_canary)!r}, os.O_RDONLY); "
            "print(json.dumps({'pid':os.getpid(),'address':ctypes.addressof(b),'fd':f}), flush=True); "
            "time.sleep(3600)"
        )
        instance.child = subprocess.Popen(
            [sys.executable, "-c", child_code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        assert instance.child.stdout is not None
        child_line = instance.child.stdout.readline().strip()
        if not child_line:
            error = instance.child.stderr.read() if instance.child.stderr else ""
            raise RuntimeError(f"supervised fixture process failed: {error}")
        child = json.loads(child_line)

        paths: dict[str, str | int] = {
            "fixture-path": str(executable),
            "fixture-directory": str(directory),
            "fixture-destination": str(destination),
            "fixture-output": str(output),
            "fixture-backup": str(backup),
            "fixture-accounting": str(accounting),
            # Ubuntu's /bin is a symlink to /usr/bin.  ToolDefinition path
            # arguments require an exact canonical registered path.
            "fixture-executable": "/usr/bin/true",
            "fixture-interpreter": "/usr/bin/dash",
            "fixture-shell": "/usr/bin/dash",
            "fixture-library": "/lib/x86_64-linux-gnu/libc.so.6",
            "fixture-module-name": "os_agent_validation_missing",
            "fixture-module-file": str(executable),
            "fixture-home": str(home),
            "fixture-user": "osagent_fixture_validation",
            "fixture-group": "osagent_fixture_validation",
            "fixture-uid": os.getuid(),
            "fixture-gid": os.getgid(),
            "fixture-fd": instance.parent_fd,
            "fixture-target-fd": int(child["fd"]),
            "fixture-pid": int(child["pid"]),
            "fixture-memory": int(child["address"]),
            "fixture-image": "alpine:3.20",
            "fixture-host": str(executable),
            "fixture-service": "os-agent-validation.service",
            "fixture-hostname": "os-agent-validation",
            "fixture-sysctl": "/proc/sys/kernel/hostname",
            # /var/run is a symlink on Ubuntu.  The ToolDefinition deliberately
            # requires a canonical exact socket path, so register /run directly.
            "fixture-docker-socket": "/run/docker.sock",
            "fixture-docker-log-root": "/var/lib/docker/containers",
            "fixture-containerd-socket": "/run/containerd/containerd.sock",
            "fixture-cgroup": "/sys/fs/cgroup",
            "fixture-cgroup-controllers": "/sys/fs/cgroup/cgroup.controllers",
            "fixture-namespace-mnt": "/proc/self/ns/mnt",
            "fixture-supervisor-socket": "/run/os-agent/host-supervisor.sock",
            "fixture-socket": str(root / "fixture.sock"),
            "fixture-timens-offsets": "/proc/self/timens_offsets",
            "fixture-systemd-runtime": "/run/systemd/system",
            "fixture-sysctl-key": "kernel.printk_ratelimit",
            "fixture-sysctl-value": "5",
            "fixture-power-reboot": "/proc/sys/kernel/ctrl-alt-del",
            "fixture-power-kexec": os.path.realpath("/sys/kernel/kexec_loaded"),
            "fixture-power-wake-alarm": os.path.realpath("/sys/class/rtc/rtc0/wakealarm"),
            "fixture-power-suspend": "/sys/power/state",
        }
        if action_name and action_name.startswith("persist.ld_preload."):
            library_source = os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")
            if not os.path.isfile(library_source):
                raise FileNotFoundError("libc fixture is unavailable")
            library = root / "fixture-library.so"
            shutil.copy2(library_source, library)
            paths["fixture-library"] = str(library)
        if action_name and action_name.startswith("persist.module_autoload."):
            # The persistence validator re-queries the configured module with
            # modprobe.  Use the kernel's harmless dummy module, while keeping
            # the value behind an explicitly registered string reference.
            paths["fixture-module-name"] = "dummy"
        if action_name and action_name.startswith("persist.systemd_trigger."):
            operation = action_name.rsplit(".", 1)[-1]
            kind = operation.removeprefix("install_") if operation.startswith("install_") else "timer"
            unit_stem = "osagent-validation-" + operation.replace("_", "-")
            trigger = Path("/run/systemd/system") / f"{unit_stem}.{kind}"
            paths["fixture-systemd-trigger"] = str(trigger)
            paths["fixture-systemd-trigger-service"] = str(trigger.with_suffix(".service"))
            paths["fixture-systemd-trigger-watch"] = str(executable)
        if action_name and action_name.startswith("persist.systemd_unit."):
            operation = action_name.rsplit(".", 1)[-1]
            paths["fixture-systemd-unit"] = str(
                Path("/run/systemd/system") / f"osagent-validation-{operation}.service"
            )
        if action_name and action_name.startswith("persist.user_systemd."):
            operation = action_name.rsplit(".", 1)[-1]
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", "user@0.service"],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ).returncode == 0
            if not active:
                subprocess.run(
                    ["systemctl", "start", "user@0.service"], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                instance.cleanup_user_manager = True
            for key, value in {
                "XDG_RUNTIME_DIR": "/run/user/0",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/0/bus",
            }.items():
                instance.saved_user_systemd_env[key] = os.environ.get(key)
                os.environ[key] = value
            unit_root = Path("/run/user/0/systemd/user")
            unit_root.mkdir(parents=True, exist_ok=True)
            paths["fixture-user-systemd-unit"] = str(
                unit_root / f"osagent-validation-{operation}.service"
            )
        if action_name and action_name.startswith("systemd.user_linger."):
            active = subprocess.run(
                ["systemctl", "is-active", "--quiet", "user@0.service"],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ).returncode == 0
            if not active:
                subprocess.run(
                    ["systemctl", "start", "user@0.service"], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                instance.cleanup_user_manager = True
            paths["fixture-linger-user"] = "root"
        if action_name and (
            action_name.startswith("docker.")
            or action_name.startswith("containerd.")
            or action_name.startswith("container.")
            or action_name.startswith("oci.runtime_run.")
            or action_name == "oci.hook_run.run"
        ):
            inspected = subprocess.run(
                ["docker", "inspect", "--format", "{{.Image}}", "os-agent-container1"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            paths["fixture-image"] = inspected.stdout.strip()
        if action_name == "docker.image_local.build":
            (directory / "Dockerfile").write_text(
                "FROM scratch\nLABEL osagent.fixture=true\n", encoding="utf-8",
            )
        if action_name == "docker.image_local.load":
            load_context = root / "load-image"
            load_context.mkdir(mode=0o700)
            (load_context / "Dockerfile").write_text(
                "FROM scratch\nLABEL osagent.fixture=true\n", encoding="utf-8",
            )
            load_tag = "osagent-validation-load:" + hashlib.sha256(
                action_name.encode("utf-8")
            ).hexdigest()[:12]
            subprocess.run(
                ["docker", "build", "--quiet", "--tag", load_tag, str(load_context)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            subprocess.run(
                ["docker", "save", "--output", str(backup), load_tag],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            subprocess.run(
                ["docker", "image", "rm", load_tag],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            instance.cleanup_images.append(load_tag)
            paths["fixture-image"] = load_tag
        if action_name == "docker.commit_export.export":
            scratch_context = root / "scratch-image"
            scratch_context.mkdir(mode=0o700)
            (scratch_context / "Dockerfile").write_text(
                "FROM scratch\nLABEL osagent.fixture=true\n",
                encoding="utf-8",
            )
            scratch_tag = "osagent-validation-scratch:" + hashlib.sha256(
                action_name.encode("utf-8")
            ).hexdigest()[:12]
            subprocess.run(
                ["docker", "build", "--quiet", "--tag", scratch_tag, str(scratch_context)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            instance.cleanup_images.append(scratch_tag)
            paths["fixture-image"] = scratch_tag
        if action_name and (action_name.startswith("oci.runtime_run.") or action_name == "oci.hook_run.run"):
            bundle = root / "oci-bundle"
            rootfs = bundle / "rootfs"
            bundle.mkdir(mode=0o700)
            rootfs.mkdir(mode=0o700)
            archive = root / "oci-rootfs.tar"
            try:
                subprocess.run(
                    ["docker", "export", "--output", str(archive), "os-agent-container1"],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                subprocess.run(
                    ["tar", "--extract", "--file", str(archive), "--directory", str(rootfs)],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                subprocess.run(
                    ["runc", "spec", "--bundle", str(bundle)],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
            except Exception:
                instance.close()
                raise
            finally:
                archive.unlink(missing_ok=True)
            config_path = bundle / "config.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["process"]["terminal"] = False
            config["process"]["args"] = ["sleep", "300"]
            config["process"]["cwd"] = "/"
            if action_name == "oci.hook_run.run":
                config["hooks"] = {
                    "prestart": [{"path": "/bin/true", "args": ["/bin/true"], "timeout": 3}],
                }
            config_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
            bundle_ref = "fixture-oci-hook-bundle" if action_name == "oci.hook_run.run" else "fixture-oci-bundle"
            paths[bundle_ref] = str(bundle)
        if action_name and action_name.startswith("kernel.module."):
            module_source = os.path.realpath(subprocess.run(
                ["modinfo", "-n", "dummy"], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            ).stdout.strip())
            if not module_source or module_source == "(builtin)" or not os.path.isfile(module_source):
                raise FileNotFoundError("safe dummy kernel module fixture is unavailable")
            module_path = root / "dummy.ko"
            with module_path.open("wb") as stream:
                subprocess.run(
                    ["zstd", "--decompress", "--stdout", module_source], check=True,
                    stdout=stream, stderr=subprocess.PIPE,
                )
            module_path.chmod(0o600)
            paths["fixture-module-name"] = "dummy"
            paths["fixture-module-file"] = str(module_path)
            if action_name == "kernel.module.unload_probe":
                subprocess.run(
                    ["modprobe", "dummy"], check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                instance.cleanup_modules.append("dummy")
        if action_name and action_name.startswith("docker.compose_local."):
            (directory / "compose.yaml").write_text(
                json.dumps({
                    "services": {
                        "osagent": {
                            "image": paths["fixture-image"],
                            "command": ["sleep", "300"],
                        },
                    },
                }),
                encoding="utf-8",
            )
        if action_name == "file.inode_flags.clear":
            subprocess.run(
                ["chattr", "+d", str(executable)],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        if action_name == "filesystem.policy_probe.setid_nosuid":
            paths["fixture-executable"] = str(executable)
        instance.resource_paths = paths
        if action_name == "exec.run.interpreter":
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
        if action_name in {"file.xattr.get", "file.xattr.remove"}:
            os.setxattr(executable, "user.osagent", b"fixture")
        return instance

    def close(self) -> None:
        if self.parent_fd is not None:
            try:
                os.close(self.parent_fd)
            except OSError:
                pass
        if self.child is not None and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=3)
        for image in self.cleanup_images:
            subprocess.run(
                ["docker", "image", "rm", "--force", image],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        for module in self.cleanup_modules:
            subprocess.run(
                ["modprobe", "-r", module],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        for key, previous in self.saved_user_systemd_env.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        if self.cleanup_user_manager:
            subprocess.run(
                ["systemctl", "stop", "user@0.service"], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )


def _reference_for_argument(name: str) -> str:
    explicit = {
        "archive_ref": "fixture-backup",
        "backup_ref": "fixture-backup",
        "context_ref": "fixture-directory",
        "dest_ref": "fixture-destination",
        "directory_ref": "fixture-directory",
        "egid_ref": "fixture-gid",
        "euid_ref": "fixture-uid",
        "executable_ref": "fixture-path",
        "fsgid_ref": "fixture-gid",
        "fsuid_ref": "fixture-uid",
        "gid_ref": "fixture-gid",
        "group_name_ref": "fixture-group",
        "home_root_ref": "fixture-home",
        "host_ref": "fixture-host",
        "hook_ref": "fixture-executable",
        "image_ref": "fixture-image",
        "interpreter_ref": "fixture-interpreter",
        "key_ref": "fixture-path",
        "library_ref": "fixture-library",
        "log_ref": "fixture-path",
        "log_root_ref": "fixture-docker-log-root",
        "lower_ref": "fixture-directory",
        "memory_ref": "fixture-memory",
        "module_file_ref": "fixture-module-file",
        "module_name_ref": "fixture-module-name",
        "output_dir_ref": "fixture-output",
        "output_ref": "fixture-output",
        "probe_ref": "fixture-path",
        "replacement_ref": "fixture-path",
        "service_ref": "fixture-service",
        "shell_ref": "fixture-shell",
        "target_fd_ref": "fixture-target-fd",
        "uid_ref": "fixture-uid",
        "upper_ref": "fixture-destination",
        "user_name_ref": "fixture-user",
        "value_ref": "fixture-path",
        "watch_ref": "fixture-path",
        "work_ref": "fixture-output",
    }
    return explicit.get(name, "fixture-path")


def _default_resource_ref(action: dict[str, Any]) -> str | None:
    kind = action["resource_kind"]
    if action["name"] == "kernel.module.load_probe":
        return "fixture-module-file"
    if action["name"] == "kernel.module.unload_probe":
        return "fixture-module-name"
    if action["name"].startswith("systemd.user_linger."):
        return "fixture-linger-user"
    if kind in {"none", "self"}:
        return None
    if kind == "pid":
        return "fixture-pid"
    if kind == "fd":
        return "fixture-fd"
    if kind == "container":
        return "fixture-docker-socket"
    if kind == "service":
        if action["name"].startswith("systemd.hostname_change."):
            return "fixture-hostname"
        return "fixture-service"
    if action["name"] == "supervisor.request.request":
        return "fixture-supervisor-socket"
    if action["name"].startswith("docker.compose_local."):
        return "fixture-directory"
    if action["name"].startswith((
        "systemd.trigger_unit.", "systemd.unit_enablement.",
        "systemd.unit_lifecycle.", "systemd.unit_property.",
    )):
        return "fixture-systemd-runtime"
    if action["name"].startswith("persist.systemd_trigger."):
        return "fixture-systemd-trigger"
    if action["name"].startswith("persist.systemd_unit."):
        return "fixture-systemd-unit"
    if action["name"].startswith("persist.user_systemd."):
        return "fixture-user-systemd-unit"
    if action["name"].startswith("volume.local_manage."):
        return "fixture-directory"
    if action["name"].startswith("unix_socket.manage."):
        return "fixture-socket"
    if action["name"].startswith("containerd."):
        return "fixture-containerd-socket"
    if action["name"].startswith("cgroup.manage."):
        return "fixture-cgroup"
    if action["name"].startswith("oci.runtime_run."):
        return "fixture-oci-bundle"
    if action["name"] == "oci.hook_run.run":
        return "fixture-oci-hook-bundle"
    if action["name"].startswith("oci."):
        return "fixture-directory"
    if action["name"] == "device.manage.rule_probe":
        return "fixture-cgroup-controllers"
    if action["name"] == "device.manage.write":
        return "fixture-backup"
    if action["name"] == "namespace.manage.enter":
        return "fixture-namespace-mnt"
    if action["name"] == "time.manage.set_namespace_offset":
        return "fixture-timens-offsets"
    if action["name"].startswith("kernel.sysctl."):
        return "fixture-sysctl"
    if action["name"].startswith("process.accounting."):
        return "fixture-accounting"
    if action["name"] == "rawio.access.write":
        return "fixture-backup"
    power_resources = {
        "power.manage.reboot_probe": "fixture-power-reboot",
        "power.manage.kexec_probe": "fixture-power-kexec",
        "power.manage.wake_alarm_probe": "fixture-power-wake-alarm",
        "power.manage.suspend_probe": "fixture-power-suspend",
    }
    if action["name"] in power_resources:
        return power_resources[action["name"]]
    if action["name"].startswith(DOCKER_SOCKET_ACTION_PREFIXES):
        return "fixture-docker-socket"
    if action["name"] in DIRECTORY_RESOURCE_ACTIONS:
        return "fixture-directory"
    return "fixture-path"


def _default_arguments(action: dict[str, Any]) -> dict[str, Any]:
    arguments: dict[str, Any] = {}
    resource_ref = _default_resource_ref(action)
    if resource_ref is not None:
        arguments["resource_ref"] = resource_ref
    schema = action["argument_schema"]
    for name in action["required_arguments"]:
        if name.endswith("_ref"):
            arguments[name] = _reference_for_argument(name)
        elif name in DEFAULT_PROFILE_VALUES:
            arguments[name] = DEFAULT_PROFILE_VALUES[name]
        elif name in DEFAULT_SCALAR_VALUES:
            arguments[name] = DEFAULT_SCALAR_VALUES[name]
        else:
            expected = schema.get(name)
            if expected == "str":
                arguments[name] = "validation"
            elif expected == "int":
                arguments[name] = 1
            elif expected == "bool":
                arguments[name] = False
            elif expected == "list":
                arguments[name] = []
            else:
                raise ValueError(f"no safe default for {action['name']} argument {name}")
    if action["name"] == "file.xattr.get":
        arguments["name"] = "user.osagent"
    if action["name"] in {"file.xattr.set", "file.xattr.remove"}:
        arguments["name"] = "user.osagent"
    if action["name"] in {"file.acl.set_access", "file.acl.set_default"}:
        arguments["entry"] = "u::rw"
    if action["name"] in {"file.inode_flags.set", "file.inode_flags.clear"}:
        arguments["flag"] = "nodump"
    if action["name"] == "file.metadata.chown":
        arguments["uid"] = os.getuid()
    if action["name"] == "process.ptrace.write":
        arguments["value"] = 0
    if action["name"] == "process.security_state.set_name":
        arguments["name"] = "osagent-probe"
    if action["name"] == "umask.set.set":
        arguments["mask"] = 0o027
    if action["name"] == "file.content.copy":
        arguments["dest_ref"] = "fixture-backup"
    if action["name"] == "oci.hook_run.create_bundle":
        arguments["hook_ref"] = "fixture-path"
    if action["name"].startswith("privilege.securebits_probe."):
        arguments["profile"] = "noroot"
    if action["name"].startswith("persist.at_job."):
        arguments["time_profile"] = "one_hour"
    if action["name"].startswith("persist.filecap."):
        arguments["capability_profile"] = "chown_ep"
    if action["name"].startswith("persist.legacy_init."):
        # The generated init script replaces resource_ref.  Pointing its exec
        # line at the same fixture would create an infinite self-exec loop.
        arguments["executable_ref"] = "fixture-executable"
    if action["name"].startswith("persist.sysctl."):
        arguments["key_ref"] = "fixture-sysctl-key"
        arguments["value_ref"] = "fixture-sysctl-value"
    if action["name"].startswith("persist.systemd_trigger."):
        arguments["service_ref"] = "fixture-systemd-trigger-service"
        arguments["executable_ref"] = "fixture-executable"
        if "watch_ref" in action["required_arguments"]:
            arguments["watch_ref"] = "fixture-systemd-trigger-watch"
    if action["name"].startswith("persist.systemd_unit."):
        arguments["executable_ref"] = "fixture-executable"
    if action["name"].startswith("persist.user_systemd."):
        arguments["executable_ref"] = "fixture-executable"
    return arguments


def _merge_overrides(arguments: dict[str, Any], action_name: str, overrides: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    item = overrides.get(action_name, {})
    if not isinstance(item, dict):
        raise ValueError(f"override for {action_name} must be an object")
    merged = dict(arguments)
    merged.update(item.get("arguments", {}))
    return merged, bool(item.get("expect_policy_blocked", False))


class EvidenceStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.sequence = 0

    def write(self, run_id: str, action_id: str, kind: str, payload: dict[str, Any]) -> str:
        self.sequence += 1
        action_root = self.root / "evidence" / action_id
        path = action_root / f"{self.sequence:03d}-{kind}.json"
        _atomic_json(path, {
            "run_id": run_id,
            "action_id": action_id,
            "kind": kind,
            "recorded_at": _now(),
            "payload": payload,
        })
        return str(path)


class CheckpointEvidenceReader:
    """Read-only adapter over evidence already persisted by this runner."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.tokens: dict[str, bool] = {}

    def _records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        evidence_root = self.root / "evidence"
        if not evidence_root.exists():
            return records
        for path in sorted(evidence_root.glob("*/*.json")):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            records.append({
                "evidence_ref": str(path),
                "run_id": item.get("run_id"),
                "action_id": item.get("action_id"),
                "source": "before_after_state",
                "kind": item.get("kind"),
            })
        return records

    def read(
        self, *, operation: str, run_id: str, action_id: str | None,
        source: str, limit: int,
    ) -> dict[str, Any]:
        del operation
        records = [
            item for item in self._records()
            if item["run_id"] == run_id
            and item["source"] == source
            and (action_id is None or item["action_id"] == action_id)
        ][:limit]
        token = "read-" + uuid.uuid4().hex
        self.tokens[token] = True
        revision_payload = "\n".join(item["evidence_ref"] for item in records)
        return {
            "records": records,
            "read_token": token,
            "store_revision": hashlib.sha256(revision_payload.encode()).hexdigest(),
            "read_only": True,
        }

    def verify_read_only(self, read_token: str) -> bool:
        return self.tokens.get(read_token) is True

    def close(self, read_token: str) -> dict[str, Any]:
        existed = self.tokens.pop(read_token, None) is True
        return {"closed": existed, "collector_mutated": False}


def _classify(execution: Any, expect_policy_blocked: bool) -> tuple[str, str]:
    result = execution.result
    if result.errno == "ETIMEDOUT":
        return "TIMEOUT", result.output
    if not execution.reset.restored:
        return "FAIL_RESETTER", execution.reset.output
    if result.outcome == "POLICY_BLOCKED":
        if expect_policy_blocked:
            return "POLICY_BLOCKED_EXPECTED", result.output
        return "INCONCLUSIVE", "unexpected policy block: " + result.output
    if result.outcome == "ERROR":
        if result.errno in {"ENOSYS", "ENOTSUP", "EOPNOTSUPP"}:
            return "UNSUPPORTED_ENV", result.output
        return "FAIL_HANDLER", result.output
    if not execution.verification.accepted:
        return "FAIL_VERIFIER", json.dumps(_json_safe(execution.verification.observed), ensure_ascii=False)
    return "PASS", f"outcome={result.outcome}; verifier={execution.verification.status}; reset={execution.reset.status}"


def _selected(actions: Iterable[dict[str, Any]], classes: set[str], names: set[str], failures: set[str]) -> list[dict[str, Any]]:
    selected = []
    for action in actions:
        if classes and action["mutation_class"] not in classes:
            continue
        if names and action["name"] not in names:
            continue
        if failures and action["name"] not in failures:
            continue
        selected.append(action)
    return selected


def _external_reset_observation(action_name: str) -> dict[str, Any]:
    if action_name in {"journal.manage.rotate_probe", "journal.manage.vacuum_probe"}:
        completed = subprocess.run(
            ["journalctl", "--disk-usage", "--no-pager"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=10,
        )
        return {
            "verified": completed.returncode == 0,
            "reset_restored": False,
            "method": "same-instance-harness-reset-observation",
            "reason": "journal rotation/vacuum is not exactly reversible on the existing host",
            "journal_disk_usage": completed.stdout.strip()[:500],
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip(),
            "command_exit": completed.returncode,
        }
    if action_name != "audit.lock.enable_probe":
        raise ValueError(f"no external reset verifier is registered for {action_name}")
    completed = subprocess.run(
        ["auditctl", "-s"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=10,
    )
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        key, separator, value = line.partition(" ")
        if separator:
            values[key] = value.strip()
    enabled = values.get("enabled")
    return {
        "verified": completed.returncode == 0 and enabled in {"0", "1"},
        "reset_restored": completed.returncode == 0 and enabled in {"0", "1"},
        "method": "same-instance-reboot",
        "audit_enabled": enabled,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip(),
        "command_exit": completed.returncode,
    }


def _acknowledge_external_resets(
    checkpoint: dict[str, Any], names: Iterable[str],
    action_by_name: dict[str, dict[str, Any]], evidence: EvidenceStore,
) -> int:
    acknowledged = 0
    for name in names:
        action = action_by_name.get(name)
        previous = checkpoint.get("results", {}).get(name)
        if action is None or previous is None:
            raise ValueError(f"cannot acknowledge unknown or unexecuted action: {name}")
        if previous.get("status") != "FAIL_RESETTER":
            raise ValueError(f"external reset acknowledgement requires FAIL_RESETTER: {name}")
        verification = previous.get("execution", {}).get("verification", {})
        if verification.get("status") not in {"VERIFIED", "VERIFIED_NO_CHANGE"}:
            raise ValueError(f"action verification was not accepted before reset: {name}")
        observed = _external_reset_observation(name)
        if not observed["verified"]:
            raise RuntimeError(f"external reset verification failed for {name}: {observed}")
        action_id = name.replace(".", "-")
        reference = evidence.write(
            checkpoint["run_id"], action_id, "external_reset_observation", observed,
        )
        reset_restored = bool(observed.get(
            "reset_restored", name == "audit.lock.enable_probe",
        ))
        previous.update(
            status="PASS" if reset_restored else "INCONCLUSIVE",
            reason=(
                "action verified; same-instance external reset independently verified"
                if reset_restored else observed.get(
                    "reason", "action verified but exact external restoration is unproven",
                )
            ),
            code_hash=action["code_hash"],
            external_reset={**observed, "evidence_ref": reference, "acknowledged_at": _now()},
        )
        acknowledged += 1
    checkpoint["updated_at"] = _now()
    return acknowledged


def _checkpoint_counts(checkpoint: dict[str, Any]) -> Counter[str]:
    return Counter(
        item.get("status", "INCONCLUSIVE")
        for item in checkpoint.get("results", {}).values()
    )


def _markdown_cell(value: Any, *, limit: int = 180) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _write_reports(
    output: Path, checkpoint: dict[str, Any], inventory: dict[str, Any],
    *, selected: int, aborted: bool,
) -> dict[str, Any]:
    results = checkpoint.get("results", {})
    counts = _checkpoint_counts(checkpoint)
    by_class: dict[str, dict[str, Any]] = {}
    action_rows: list[dict[str, Any]] = []
    untested: list[str] = []
    blockers: list[dict[str, Any]] = []
    for action in inventory["actions"]:
        mutation_class = action["mutation_class"]
        bucket = by_class.setdefault(
            mutation_class, {"total": 0, "executed": 0, "counts": {}},
        )
        bucket["total"] += 1
        result = results.get(action["name"])
        if result is None:
            status = "UNTESTED"
            reason = "not executed"
            untested.append(action["name"])
        else:
            status = result.get("status", "INCONCLUSIVE")
            reason = result.get("reason", "")
            bucket["executed"] += 1
            bucket["counts"][status] = bucket["counts"].get(status, 0) + 1
        row = {
            "name": action["name"], "tool": action["tool"],
            "action": action["action"], "mutation_class": mutation_class,
            "status": status, "reason": reason,
            "code_hash": action["code_hash"],
        }
        action_rows.append(row)
        if status not in {"PASS", "POLICY_BLOCKED_EXPECTED", "UNTESTED"}:
            blockers.append(row)

    if any(counts[item] for item in {"FAIL_HANDLER", "FAIL_VERIFIER", "FAIL_RESETTER", "TIMEOUT"}):
        outcome = "FAILED"
    elif untested:
        outcome = "INCOMPLETE"
    elif counts["INCONCLUSIVE"] or counts["UNSUPPORTED_ENV"]:
        outcome = "COMPLETE_WITH_LIMITATIONS"
    else:
        outcome = "PASS"
    report = {
        "schema_version": "tool-validation-report-v1",
        "run_id": checkpoint["run_id"], "generated_at": _now(),
        "outcome": outcome, "aborted": aborted, "selected_in_last_invocation": selected,
        "inventory": {
            "tools": inventory["summary"]["tools"],
            "actions": inventory["summary"]["actions"],
        },
        "executed": len(results), "untested_count": len(untested),
        "counts": dict(sorted(counts.items())), "by_mutation_class": by_class,
        "blockers": blockers, "untested": untested, "actions": action_rows,
        "checkpoint": str(output / "checkpoint.json"),
    }
    _atomic_json(output / "report.json", report)

    lines = [
        "# Live ToolDefinition validation report", "",
        f"- Run ID: `{_markdown_cell(report['run_id'])}`",
        f"- Outcome: **{outcome}**",
        f"- Inventory: **{report['inventory']['tools']} Tools / {report['inventory']['actions']} Actions**",
        f"- Executed: **{report['executed']}**; untested: **{report['untested_count']}**",
        f"- Aborted by reset guard: **{str(aborted).lower()}**", "",
        "## Result counts", "", "| Status | Count |", "| --- | ---: |",
    ]
    for status in sorted(RESULT_STATUSES | {"UNTESTED"}):
        value = len(untested) if status == "UNTESTED" else counts[status]
        lines.append(f"| `{status}` | {value} |")
    lines.extend(["", "## Mutation-class coverage", "", "| Class | Executed | Total | Results |", "| --- | ---: | ---: | --- |"])
    for mutation_class, bucket in sorted(by_class.items()):
        result_text = ", ".join(f"{key}={value}" for key, value in sorted(bucket["counts"].items())) or "none"
        lines.append(
            f"| `{mutation_class}` | {bucket['executed']} | {bucket['total']} | {_markdown_cell(result_text)} |"
        )
    lines.extend(["", "## Action results", "", "| Action | Class | Status | Reason |", "| --- | --- | --- | --- |"])
    for row in action_rows:
        lines.append(
            f"| `{_markdown_cell(row['name'])}` | `{row['mutation_class']}` | `{row['status']}` | {_markdown_cell(row['reason'])} |"
        )
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def run(arguments: argparse.Namespace) -> int:
    output = arguments.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checkpoint_path = output / "checkpoint.json"
    progress_path = output / "progress.json"
    inventory = build_inventory()
    action_by_name = {item["name"]: item for item in inventory["actions"]}
    checkpoint: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "run_id": arguments.run_id or f"tool-validation-{uuid.uuid4().hex[:12]}",
        "created_at": _now(),
        "updated_at": _now(),
        "results": {},
    }
    if arguments.resume and checkpoint_path.exists():
        checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    evidence = EvidenceStore(output)
    acknowledged = _acknowledge_external_resets(
        checkpoint, arguments.acknowledge_reset, action_by_name, evidence,
    )
    if acknowledged:
        _atomic_json(checkpoint_path, checkpoint)
        if not arguments.mutation_class and not arguments.action and not arguments.failures_only:
            summary = {
                "schema_version": SCHEMA_VERSION,
                "run_id": checkpoint["run_id"],
                "generated_at": _now(),
                "acknowledged_external_resets": acknowledged,
                "checkpoint": str(checkpoint_path),
            }
            _atomic_json(output / "summary.json", summary)
            print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
            return 0
    if arguments.report_only:
        report = _write_reports(output, checkpoint, inventory, selected=0, aborted=False)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0
    overrides = {}
    if arguments.overrides:
        overrides = json.loads(arguments.overrides.read_text(encoding="utf-8"))
    failure_names = {
        name for name, result in checkpoint.get("results", {}).items()
        if result.get("status") in TERMINAL_FAILURES
    } if arguments.failures_only else set()
    selected = _selected(
        inventory["actions"], set(arguments.mutation_class), set(arguments.action), failure_names,
    )
    if arguments.limit:
        selected = selected[: arguments.limit]
    evidence_reader = CheckpointEvidenceReader(output)
    counts: Counter[str] = Counter()
    aborted = False

    for index, action in enumerate(selected, 1):
        previous = checkpoint["results"].get(action["name"])
        if (
            arguments.resume and not arguments.failures_only and previous
            and previous.get("status") in RESUME_COMPLETE_STATUSES
            and previous.get("code_hash") == action["code_hash"]
        ):
            counts[previous["status"]] += 1
            continue
        action_id = action["name"].replace(".", "-")
        action_root = output / "fixtures" / action_id
        started = time.monotonic()
        record: dict[str, Any] = {
            "action": action["name"], "tool": action["tool"], "operation": action["action"],
            "code_hash": action["code_hash"], "mutation_class": action["mutation_class"],
            "started_at": _now(), "executor": "host", "trust_boundary": "TB-HH-U1U2",
        }
        fixture: Fixture | None = None
        try:
            fixture = Fixture.create(action_root, action["name"])
            before_hash = _tree_hash(action_root)
            action_arguments, expect_policy = _merge_overrides(
                _default_arguments(action), action["name"], overrides,
            )
            allowed_targets = frozenset(fixture.resource_paths)
            guard = RunGuard()
            context = ToolContext(
                run_id=checkpoint["run_id"], action_id=action_id,
                executor_mode="host", trust_boundary_id="TB-HH-U1U2",
                source="u1", target="u2", allowed_targets=allowed_targets,
                resource_paths=fixture.resource_paths,
                destructive_enabled=bool(action["destructive"]), run_guard=guard,
                evidence_writer=evidence.write,
            )
            definition_state = (
                {"evidence_reader": evidence_reader}
                if action["tool"] == "evidence.feedback" else {}
            )
            execution = execute_tool_action(
                action["tool"], action["action"], action_arguments, context,
                state=definition_state,
            )
            status, reason = _classify(execution, expect_policy)
            after_hash = _tree_hash(action_root)
            record.update({
                "status": status, "reason": reason, "arguments": action_arguments,
                "fixture_hash_before": before_hash, "fixture_hash_after": after_hash,
                "fixture_hash_restored": before_hash == after_hash,
                "execution": execution.to_dict(), "guard_aborted": guard.aborted,
            })
            if status == "PASS" and before_hash != after_hash and action["mutation_class"] == "observational":
                record["status"] = "FAIL_RESETTER"
                record["reason"] = "observational action changed its dedicated fixture tree"
            if guard.aborted or record["status"] == "FAIL_RESETTER":
                aborted = True
        except (FileNotFoundError, NotImplementedError) as exc:
            record.update(status="UNSUPPORTED_ENV", reason=str(exc))
        except Exception as exc:
            record.update(status="INCONCLUSIVE", reason=f"runner error: {type(exc).__name__}: {exc}")
        finally:
            if fixture is not None:
                fixture.close()
        record["finished_at"] = _now()
        record["duration_seconds"] = round(time.monotonic() - started, 3)
        if record["status"] not in RESULT_STATUSES:
            raise RuntimeError(f"invalid result status: {record['status']}")
        counts[record["status"]] += 1
        checkpoint["results"][action["name"]] = record
        checkpoint["updated_at"] = _now()
        _atomic_json(checkpoint_path, checkpoint)
        _atomic_json(progress_path, {
            "run_id": checkpoint["run_id"], "updated_at": _now(),
            "position": index, "selected": len(selected), "current": action["name"],
            "invocation_counts": dict(counts),
            "checkpoint_counts": dict(_checkpoint_counts(checkpoint)),
            "executed": len(checkpoint["results"]),
            "inventory_actions": inventory["summary"]["actions"],
            "aborted": aborted,
        })
        print(f"[{index}/{len(selected)}] {action['name']}: {record['status']}", flush=True)
        if aborted:
            print("Run aborted because reset verification failed.", file=sys.stderr, flush=True)
            break

    report = _write_reports(output, checkpoint, inventory, selected=len(selected), aborted=aborted)
    summary = {
        "schema_version": SCHEMA_VERSION, "run_id": checkpoint["run_id"],
        "generated_at": _now(), "selected": len(selected),
        "invocation_counts": dict(counts),
        "checkpoint_counts": report["counts"], "executed": report["executed"],
        "untested": report["untested_count"], "outcome": report["outcome"],
        "aborted": aborted, "checkpoint": str(checkpoint_path),
        "report_json": str(output / "report.json"),
        "report_markdown": str(output / "report.md"),
    }
    _atomic_json(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 2 if aborted else (1 if any(counts[item] for item in TERMINAL_FAILURES) else 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--overrides", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--failures-only", action="store_true")
    parser.add_argument("--report-only", action="store_true")
    parser.add_argument("--acknowledge-reset", action="append", default=[])
    parser.add_argument("--mutation-class", action="append", default=[])
    parser.add_argument("--action", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

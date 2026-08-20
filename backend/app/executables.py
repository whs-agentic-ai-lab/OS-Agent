from functools import lru_cache
import os
from pathlib import Path
import shutil
import subprocess


def executable_candidates(name: str) -> list[str]:
    candidates: list[str] = []
    if name == "aws" and os.name == "nt":
        local_app_data = os.getenv("LOCALAPPDATA")
        if local_app_data:
            candidates.append(
                str(Path(local_app_data) / "Programs" / "Amazon" / "AWSCLIV2" / "aws.exe")
            )
        for root in (os.getenv("ProgramFiles"), os.getenv("ProgramW6432")):
            if root:
                candidates.append(str(Path(root) / "Amazon" / "AWSCLIV2" / "aws.exe"))
    discovered = shutil.which(name)
    if discovered:
        candidates.append(discovered)
    return list(dict.fromkeys(candidates))


def find_working_executable(name: str, version_args: list[str]) -> str | None:
    return _find_working_executable(name, tuple(version_args))


@lru_cache(maxsize=16)
def _find_working_executable(name: str, version_args: tuple[str, ...]) -> str | None:
    for executable in executable_candidates(name):
        if not Path(executable).is_file():
            continue
        try:
            completed = subprocess.run(
                [executable, *version_args],
                capture_output=True,
                timeout=10,
                check=False,
            )
            if completed.returncode == 0:
                return executable
        except (OSError, subprocess.SubprocessError):
            continue
    return None

import pytest

from app.permission_minimizer import (
    atom_ids_for_profiles,
    build_profiles,
    collect_maximum_permission_profiles,
    relevant_atom_ids,
)
from app.schemas import SubjectMode


def test_maximum_profile_turns_defensive_no_new_privileges_off() -> None:
    profiles = collect_maximum_permission_profiles()

    assert profiles.host["owner_write"] is True
    assert profiles.host["no_new_privileges"] is False
    assert profiles.container["privileged"] is True
    assert profiles.container["run_as_root"] is True
    assert profiles.container["no_new_privileges"] is False
    assert "host:no_new_privileges=OFF" in atom_ids_for_profiles(profiles)


def test_profile_builder_does_not_hide_privileged_dependency() -> None:
    with pytest.raises(ValueError, match="run_as_root"):
        build_profiles({"container:privileged"})


def test_file_write_relevant_ids_are_ids_not_policy_document() -> None:
    ids = relevant_atom_ids(
        SubjectMode.container,
        "file.content",
        "write",
    )

    assert ids == [
        "container:mount_write",
        "container:run_as_root",
        "container:supplementary_group",
        "container:dac_override",
    ]
    assert all(":" in item and "{" not in item for item in ids)

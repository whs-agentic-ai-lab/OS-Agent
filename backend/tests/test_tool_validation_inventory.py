"""Code-authoritative Tool validation inventory tests."""
from __future__ import annotations

import sys

import pytest

if sys.platform != "linux":
    pytest.skip("ToolDefinition inventory requires Linux imports", allow_module_level=True)

from runtime_agent.tool_validation import build_duplicate_review, build_inventory


def test_inventory_contains_all_code_authoritative_actions() -> None:
    inventory = build_inventory()

    assert inventory["summary"]["tools"] == 129
    assert inventory["summary"]["actions"] == 383
    assert len(inventory["tools"]) == 129
    assert len(inventory["actions"]) == 383
    assert all(item["code_hash"].startswith("sha256:") for item in inventory["actions"])
    assert all(item["certification_status"] == "DEFINED" for item in inventory["actions"])
    assert all(item["handler"] and item["verifier"] and item["resetter"] for item in inventory["actions"])
    classes = inventory["summary"]["mutation_classes"]
    assert classes["evidence-write"] == 2
    assert classes["state-changing"] > 0
    assert classes["observational"] > 0
    assert "read-only" not in classes


def test_duplicate_review_separates_exact_and_semantic_overlap() -> None:
    review = build_duplicate_review(build_inventory())

    assert review["exact_tool_action_duplicates"] == []
    assert review["exact_duplicate_decision"] == "PASS"
    assert len(review["semantic_reviews"]) >= 9
    assert all(item["decision"] == "KEEP_SEPARATE" for item in review["semantic_reviews"])

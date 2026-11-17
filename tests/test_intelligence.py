from __future__ import annotations

import json
from pathlib import Path

import pytest

from youtube_forensics.core import atomic_json, build_receipt
from youtube_forensics.intelligence import (
    build_feedback,
    build_intelligence,
    normalize_tags,
    score_post,
)


def make_evidence(root: Path, *, metadata: dict) -> Path:
    root.mkdir()
    atomic_json(root / "metadata.json", metadata)
    build_receipt(
        root,
        input_value="https://www.youtube.com/watch?v=bc7QaDmLmoA",
        network_used=True,
        acquisition={"source": "youtube"},
        video=None,
    )
    return root


def test_intelligence_binds_receipt_and_preserves_unknowns(tmp_path: Path) -> None:
    job = make_evidence(
        tmp_path / "job",
        metadata={
            "id": "bc7QaDmLmoA",
            "title": "Build a local creative system",
            "description": "Build private AI tools and follow for more. #LocalAI #Privacy",
            "tags": ["AI", "privacy"],
            "view_count": 1500,
            "like_count": 100,
            "comment_count": 20,
        },
    )
    original_receipt = (job / "receipt.json").read_bytes()
    result = build_intelligence(
        [job],
        platform="youtube",
        proposed_caption="Build private local AI tools and follow for more useful guides.",
        proposed_tags=["localai", "privacy", "opensource"],
    )
    receipt = json.loads(original_receipt)
    assert result["source_receipts"] == [receipt["receipt_sha256"]]
    assert result["observations"][0]["unknown_metrics"] == ["share_count", "repost_count"]
    assert result["tag_intelligence"]["grounded_in_observed_tags"] is True
    assert result["proposed_post"]["assessment"]["platform"] == "youtube"
    assert (job / "receipt.json").read_bytes() == original_receipt


def test_identical_inputs_produce_identical_intelligence(tmp_path: Path) -> None:
    job = make_evidence(
        tmp_path / "job",
        metadata={"id": "bc7QaDmLmoA", "title": "Stable result", "tags": ["testing"]},
    )
    left = build_intelligence([job], platform="youtube")
    right = build_intelligence([job], platform="youtube")
    assert left == right


def test_tampered_evidence_is_refused(tmp_path: Path) -> None:
    job = make_evidence(tmp_path / "job", metadata={"id": "bc7QaDmLmoA"})
    (job / "metadata.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not verified"):
        build_intelligence([job], platform="youtube")


def test_feedback_is_append_only_and_hash_bound(tmp_path: Path) -> None:
    job = make_evidence(
        tmp_path / "job",
        metadata={"id": "bc7QaDmLmoA", "title": "Feedback", "tags": ["ai"]},
    )
    intelligence = build_intelligence([job], platform="youtube")
    feedback = build_feedback(
        intelligence,
        metrics={"view_count": 2000, "like_count": 150, "comment_count": 30},
    )
    assert feedback["intelligence_sha256"] == intelligence["artifact_sha256"]
    assert feedback["reach_signal"] == 212.0
    changed = dict(intelligence)
    changed["platform"] = "tiktok"
    with pytest.raises(ValueError, match="hash mismatch"):
        build_feedback(changed, metrics={"view_count": 1})


def test_platform_scoring_and_normalization() -> None:
    assert normalize_tags([" #AI ", "ai", "Privacy"]) == ["ai", "privacy"]
    strong = score_post(
        "Build private local AI tools today and follow for more useful guides.",
        ["ai", "local", "privacy"],
        "youtube",
    )
    weak = score_post("buy", ["one", "two", "three", "four", "five", "sixteen"], "x")
    assert strong["score"] > weak["score"]

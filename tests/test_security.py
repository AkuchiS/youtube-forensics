from __future__ import annotations

import json
from pathlib import Path

import pytest

from youtube_forensics.core import (
    atomic_json,
    build_receipt,
    canonical,
    prepare_output,
    sha256_bytes,
    verify_job,
)


def rewrite_receipt(path: Path, mutate) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    value.pop("receipt_sha256")
    mutate(value)
    value["receipt_sha256"] = sha256_bytes(canonical(value))
    atomic_json(path, value)


def test_verifier_rejects_unexpected_artifact(tmp_path: Path) -> None:
    (tmp_path / "known.txt").write_text("known", encoding="utf-8")
    build_receipt(tmp_path, input_value="local", network_used=False, acquisition=None, video=None)
    (tmp_path / "injected.txt").write_text("not in manifest", encoding="utf-8")
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert "unexpected artifact: injected.txt" in result["problems"]


def test_verifier_rejects_unexpected_empty_directory(tmp_path: Path) -> None:
    build_receipt(tmp_path, input_value="local", network_used=False, acquisition=None, video=None)
    (tmp_path / "injected-empty").mkdir()
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert "unexpected directory: injected-empty" in result["problems"]


def test_verifier_rejects_wrong_schema_even_with_valid_hash(tmp_path: Path) -> None:
    build_receipt(tmp_path, input_value="local", network_used=False, acquisition=None, video=None)
    receipt = tmp_path / "receipt.json"
    rewrite_receipt(receipt, lambda value: value.update({"schema": "unknown/v99"}))
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert "unsupported receipt schema" in result["problems"]


def test_verifier_rejects_symlinked_receipt(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-receipt.json"
    outside.write_text("{}", encoding="utf-8")
    (tmp_path / "receipt.json").symlink_to(outside)
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert result["problems"] == ["invalid receipt: symlink"]


@pytest.mark.parametrize("hostile", ["../outside.txt", "/tmp/outside.txt", "a/../../outside"])
def test_verifier_rejects_hostile_manifest_paths(tmp_path: Path, hostile: str) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    build_receipt(tmp_path, input_value="local", network_used=False, acquisition=None, video=None)
    receipt = tmp_path / "receipt.json"
    rewrite_receipt(receipt, lambda value: value["files"].update({hostile: "0" * 64}))
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert any("unsafe artifact path" in item for item in result["problems"])


def test_verifier_rejects_symlink(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(outside)
    build_receipt(tmp_path, input_value="local", network_used=False, acquisition=None, video=None)
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert "unexpected artifact: link.txt" in result["problems"]


@pytest.mark.parametrize("body", ["null", "[]", "not-json"])
def test_verifier_handles_malformed_receipt(tmp_path: Path, body: str) -> None:
    (tmp_path / "receipt.json").write_text(body, encoding="utf-8")
    result = verify_job(tmp_path)
    assert result["verified"] is False
    assert result["problems"]


def test_prepare_output_rejects_non_checkpoint_files(tmp_path: Path) -> None:
    job = tmp_path / "job"
    job.mkdir()
    (job / "unrelated.txt").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="non-checkpoint artifacts"):
        prepare_output(job, resume=True)


def test_prepare_output_accepts_narrow_checkpoint_shape(tmp_path: Path) -> None:
    job = tmp_path / "job"
    job.mkdir()
    (job / ".frame-index.partial.jsonl").write_text("{}\n", encoding="utf-8")
    (job / ".frame-checkpoint.json").write_text("{}\n", encoding="utf-8")
    (job / "retained-frames").mkdir()
    assert prepare_output(job, resume=True) == job.resolve()


def test_prepare_output_rejects_symlink_checkpoint(tmp_path: Path) -> None:
    job = tmp_path / "job"
    job.mkdir()
    target = tmp_path / "target"
    target.write_text("{}\n", encoding="utf-8")
    (job / ".frame-index.partial.jsonl").symlink_to(target)
    (job / ".frame-checkpoint.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="symlinks"):
        prepare_output(job, resume=True)


def test_atomic_json_leaves_valid_complete_file(tmp_path: Path) -> None:
    target = tmp_path / "value.json"
    atomic_json(target, {"b": 2, "a": 1})
    assert target.read_bytes() == b'{"a":1,"b":2}\n'
    assert not list(tmp_path.glob(".*.tmp"))

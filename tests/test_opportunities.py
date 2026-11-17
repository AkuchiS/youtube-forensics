from __future__ import annotations

import json
from pathlib import Path

import pytest

from youtube_forensics.core import atomic_json, build_receipt
from youtube_forensics.opportunities import build_opportunity_radar


def evidence(root: Path, metadata: dict, *, enveloped: bool = True) -> Path:
    root.mkdir()
    value = (
        {
            "schema": "youtube-forensics.youtube-metadata/v1",
            "metadata": metadata,
            "classification": "PUBLIC_METADATA_UNVERIFIED",
        }
        if enveloped
        else metadata
    )
    atomic_json(root / "metadata.json", value)
    build_receipt(
        root,
        input_value=f"https://www.youtube.com/watch?v={metadata['id']}",
        network_used=True,
        acquisition={"source": "youtube"},
        video=None,
    )
    return root


def corpus(tmp_path: Path) -> list[Path]:
    rows = [
        ("a1", "chan-a", 100, ["quiet"], "Quiet workflow"),
        ("a2", "chan-a", 120, ["quiet"], "Quiet routine"),
        ("a3", "chan-a", 1000, ["local-ai"], "Local AI breakthrough"),
        ("b1", "chan-b", 80, ["baseline"], "Baseline workflow"),
        ("b2", "chan-b", 100, ["baseline"], "Baseline routine"),
        ("b3", "chan-b", 720, ["local-ai"], "Local AI tutorial"),
    ]
    return [
        evidence(
            tmp_path / video_id,
            {
                "id": video_id,
                "channel_id": channel,
                "channel": channel,
                "title": title,
                "tags": tags,
                "view_count": views,
                "channel_follower_count": 200,
            },
        )
        for video_id, channel, views, tags, title in rows
    ]


def test_radar_finds_leave_one_out_outliers_and_cross_channel_topic(tmp_path: Path) -> None:
    result = build_opportunity_radar(corpus(tmp_path))
    assert result["schema"] == "argus.opportunity-radar/v1"
    assert result["ranked_videos"][0]["source_id"] == "a3"
    assert result["ranked_videos"][0]["baseline_view_count"] == 110
    assert result["ranked_videos"][0]["outlier_multiplier"] == pytest.approx(9.090909)
    topic = next(row for row in result["topic_candidates"] if row["topic"] == "local-ai")
    assert topic["independent_channels"] == 2
    assert topic["qualified_outliers"] == 2
    assert topic["classification"] == "OBSERVED_CROSS_CHANNEL_CANDIDATE"


def test_radar_is_deterministic_hash_bound_and_preserves_unknowns(tmp_path: Path) -> None:
    jobs = corpus(tmp_path)
    first = build_opportunity_radar(jobs)
    second = build_opportunity_radar(reversed(jobs))
    assert first == second
    assert first["coverage"]["missing_fields"]["channel_follower_count"] == 0
    assert len(first["source_receipts"]) == 6


def test_small_channel_samples_do_not_claim_outliers(tmp_path: Path) -> None:
    jobs = [
        evidence(
            tmp_path / f"x{number}",
            {
                "id": f"x{number}",
                "channel_id": "small",
                "title": "Unqualified",
                "view_count": views,
            },
            enveloped=False,
        )
        for number, views in enumerate((10, 100), start=1)
    ]
    result = build_opportunity_radar(jobs)
    assert all(row["outlier_multiplier"] is None for row in result["ranked_videos"])
    assert all(
        row["qualification"] == "INSUFFICIENT_CHANNEL_BASELINE"
        for row in result["ranked_videos"]
    )
    assert result["topic_candidates"] == []


def test_tamper_and_duplicate_receipts_fail_closed(tmp_path: Path) -> None:
    jobs = corpus(tmp_path)
    (jobs[0] / "metadata.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not verified"):
        build_opportunity_radar(jobs)

    one = evidence(
        tmp_path / "one",
        {"id": "same", "channel_id": "same", "view_count": 1},
    )
    copied = tmp_path / "copied"
    copied.mkdir()
    for name in ("metadata.json", "receipt.json"):
        (copied / name).write_bytes((one / name).read_bytes())
    with pytest.raises(ValueError, match="distinct receipt"):
        build_opportunity_radar([one, copied])


def test_metadata_envelope_is_used_by_existing_intelligence(tmp_path: Path) -> None:
    from youtube_forensics.intelligence import build_intelligence

    job = evidence(
        tmp_path / "wrapped",
        {
            "id": "wrapped",
            "channel_id": "channel",
            "title": "Envelope title",
            "tags": ["wrapped"],
            "view_count": 4,
        },
    )
    result = build_intelligence([job], platform="youtube")
    assert result["observations"][0]["source_id"] == "wrapped"
    assert result["observations"][0]["title"] == "Envelope title"
    json.dumps(result)

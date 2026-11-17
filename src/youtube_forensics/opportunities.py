from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .core import canonical, sha256_bytes, sha256_file
from .intelligence import _keywords, _load_verified_job, normalize_tags

OPPORTUNITY_SCHEMA = "argus.opportunity-radar/v1"
RULESET_VERSION = "argus-outlier-r1"


def _nonnegative_number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = float(value)
        if math.isfinite(value) and value >= 0:
            return value
    return None


def _video_record(metadata: dict[str, Any], receipt: str) -> dict[str, Any]:
    source_id = str(metadata.get("id") or "").strip()
    channel_id = str(metadata.get("channel_id") or metadata.get("uploader_id") or "").strip()
    channel = str(metadata.get("channel") or metadata.get("uploader") or "").strip()
    views = _nonnegative_number(metadata.get("view_count"))
    followers = _nonnegative_number(metadata.get("channel_follower_count"))
    tags = normalize_tags(metadata.get("tags") or [])
    categories = normalize_tags(metadata.get("categories") or [])
    title = str(metadata.get("title") or "")
    topics = sorted(set(tags + categories + _keywords(title, limit=20)))
    return {
        "source_id": source_id or None,
        "channel_key": channel_id or channel or None,
        "channel_id": channel_id or None,
        "channel": channel or None,
        "title": title,
        "view_count": views,
        "channel_follower_count": followers,
        "topics": topics,
        "source_receipt": receipt,
    }


def _rank_outliers(records: list[dict[str, Any]], minimum_channel_samples: int) -> None:
    by_channel: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["channel_key"] and record["view_count"] is not None:
            by_channel[record["channel_key"]].append(record)

    for record in records:
        record["qualification"] = "INSUFFICIENT_CHANNEL_BASELINE"
        record["channel_sample_size"] = 0
        record["baseline_view_count"] = None
        record["outlier_multiplier"] = None
        record["views_per_follower"] = None
        if record["channel_key"]:
            peers = by_channel.get(record["channel_key"], [])
            record["channel_sample_size"] = len(peers)
            if len(peers) >= minimum_channel_samples and record["view_count"] is not None:
                peer_views = [
                    peer["view_count"] for peer in peers if peer is not record
                ]
                baseline = statistics.median(peer_views)
                record["baseline_view_count"] = baseline
                record["qualification"] = (
                    "ZERO_CHANNEL_BASELINE" if baseline == 0 else "QUALIFIED"
                )
                if baseline > 0:
                    record["outlier_multiplier"] = round(record["view_count"] / baseline, 6)
        followers = record["channel_follower_count"]
        if followers and record["view_count"] is not None:
            record["views_per_follower"] = round(record["view_count"] / followers, 6)


def _topic_candidates(
    records: list[dict[str, Any]], minimum_topic_channels: int
) -> list[dict[str, Any]]:
    topic_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        for topic in record["topics"]:
            topic_records[topic].append(record)

    candidates = []
    for topic, matches in topic_records.items():
        channels = {row["channel_key"] for row in matches if row["channel_key"]}
        qualified = [
            row["outlier_multiplier"]
            for row in matches
            if row["outlier_multiplier"] is not None
        ]
        if len(channels) < minimum_topic_channels or not qualified:
            continue
        candidates.append(
            {
                "topic": topic,
                "videos": len(matches),
                "independent_channels": len(channels),
                "qualified_outliers": len(qualified),
                "median_outlier_multiplier": round(statistics.median(qualified), 6),
                "maximum_outlier_multiplier": round(max(qualified), 6),
                "classification": "OBSERVED_CROSS_CHANNEL_CANDIDATE",
            }
        )
    return sorted(
        candidates,
        key=lambda row: (
            -row["median_outlier_multiplier"],
            -row["independent_channels"],
            -row["videos"],
            row["topic"],
        ),
    )


def build_opportunity_radar(
    evidence_jobs: Iterable[Path],
    *,
    minimum_channel_samples: int = 3,
    minimum_topic_channels: int = 2,
) -> dict[str, Any]:
    jobs = [Path(job) for job in evidence_jobs]
    if not jobs:
        raise ValueError("At least one verified evidence package is required")
    if len(jobs) > 5000:
        raise ValueError("At most 5000 evidence packages may be compared at once")
    if not 3 <= minimum_channel_samples <= 1000:
        raise ValueError("minimum_channel_samples must be between 3 and 1000")
    if not 2 <= minimum_topic_channels <= 1000:
        raise ValueError("minimum_topic_channels must be between 2 and 1000")

    loaded = [_load_verified_job(job) for job in jobs]
    receipts = [item["receipt"].get("receipt_sha256") for item in loaded]
    if any(not isinstance(receipt, str) for receipt in receipts):
        raise ValueError("Every evidence package must have a receipt hash")
    if len(set(receipts)) != len(receipts):
        raise ValueError("Every evidence package must have a distinct receipt")

    records = [
        _video_record(item["metadata"], item["receipt"]["receipt_sha256"])
        for item in loaded
    ]
    _rank_outliers(records, minimum_channel_samples)
    ranked = sorted(
        records,
        key=lambda row: (
            row["outlier_multiplier"] is None,
            -(row["outlier_multiplier"] or 0),
            row["source_id"] or "",
            row["source_receipt"],
        ),
    )
    missing = {
        "source_id": sum(row["source_id"] is None for row in records),
        "channel": sum(row["channel_key"] is None for row in records),
        "view_count": sum(row["view_count"] is None for row in records),
        "channel_follower_count": sum(
            row["channel_follower_count"] is None for row in records
        ),
    }
    artifact = {
        "schema": OPPORTUNITY_SCHEMA,
        "status": "OPPORTUNITY_RADAR_READY_REVIEW_REQUIRED",
        "source_receipts": sorted(receipts),
        "engine": {
            "name": "ARGUS Opportunity Radar",
            "ruleset": RULESET_VERSION,
            "implementation_sha256": sha256_file(Path(__file__)),
        },
        "parameters": {
            "minimum_channel_samples": minimum_channel_samples,
            "minimum_topic_channels": minimum_topic_channels,
            "channel_baseline": "leave_one_out_median_views",
        },
        "coverage": {
            "evidence_packages": len(records),
            "missing_fields": missing,
        },
        "ranked_videos": ranked,
        "topic_candidates": _topic_candidates(records, minimum_topic_channels),
        "limitations": [
            "A video is an outlier only relative to the supplied channel sample.",
            "A topic candidate is observed correlation, not proof of market demand or profit.",
            "Missing views, channels and follower counts remain unknown and are not estimated.",
            "This artifact does not authorize scraping, publishing, spending or product claims.",
        ],
    }
    artifact["artifact_sha256"] = sha256_bytes(canonical(artifact))
    return artifact


__all__ = ["OPPORTUNITY_SCHEMA", "build_opportunity_radar"]

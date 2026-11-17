from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .core import canonical, sha256_bytes, sha256_file, verify_job

INTELLIGENCE_SCHEMA = "argus.intelligence/v1"
FEEDBACK_SCHEMA = "argus.performance-feedback/v1"
RULESET_VERSION = "argus-amplify-r1"
TAG_RE = re.compile(r"#([\w]+)", re.UNICODE)
WORD_RE = re.compile(r"[a-z0-9]{4,}")
CTA_RE = re.compile(
    r"\b(link in bio|comment|follow|save this|share|sign ?up|try|download|get|"
    r"learn|read more|subscribe|join)\b",
    re.IGNORECASE,
)

# Public platform limits and a deliberately small recommended tag range.  The
# collector records what it observed; these rules only produce a recommendation.
PLATFORM_RULES: dict[str, dict[str, Any]] = {
    "instagram": {"max_chars": 2200, "tag_range": (3, 5), "tag_ceiling": 30},
    "tiktok": {"max_chars": 2200, "tag_range": (4, 5), "tag_ceiling": 8},
    "facebook": {"max_chars": 63206, "tag_range": (1, 2), "tag_ceiling": 3},
    "linkedin": {"max_chars": 3000, "tag_range": (3, 5), "tag_ceiling": 8},
    "x": {"max_chars": 280, "tag_range": (1, 2), "tag_ceiling": 3},
    "youtube": {"max_chars": 5000, "tag_range": (3, 5), "tag_ceiling": 15},
    "threads": {"max_chars": 500, "tag_range": (1, 3), "tag_ceiling": 5},
    "bluesky": {"max_chars": 300, "tag_range": (1, 3), "tag_ceiling": 5},
    "mastodon": {"max_chars": 500, "tag_range": (2, 4), "tag_ceiling": 6},
    "reddit": {"max_chars": 40000, "tag_range": (0, 0), "tag_ceiling": 0},
}

DEFAULT_RULE = {"max_chars": 2200, "tag_range": (2, 5), "tag_ceiling": 10}
STOP_WORDS = {
    "about",
    "after",
    "again",
    "also",
    "because",
    "before",
    "from",
    "have",
    "into",
    "just",
    "like",
    "more",
    "that",
    "their",
    "there",
    "these",
    "they",
    "this",
    "what",
    "when",
    "where",
    "which",
    "with",
    "would",
    "your",
}


def normalize_tags(tags: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in tags:
        tag = str(value or "").strip().lstrip("#").strip().lower()
        if tag and tag not in result:
            result.append(tag)
    return result


def extract_tags(text: str) -> list[str]:
    return normalize_tags(TAG_RE.findall(text or ""))


def _keywords(text: str, limit: int = 12) -> list[str]:
    result: list[str] = []
    for word in WORD_RE.findall((text or "").lower()):
        if word not in STOP_WORDS and word not in result:
            result.append(word)
        if len(result) == limit:
            break
    return result


def _load_verified_job(job: Path) -> dict[str, Any]:
    job = Path(job).expanduser()
    verification = verify_job(job)
    if verification.get("verified") is not True:
        problems = "; ".join(verification.get("problems") or ["verification failed"])
        raise ValueError(f"Evidence package is not verified: {problems}")
    receipt = json.loads((job / "receipt.json").read_text(encoding="utf-8"))
    metadata_path = job / "metadata.json"
    metadata = (
        json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else {}
    )
    if not isinstance(metadata, dict):
        raise ValueError("metadata.json must contain an object")
    if metadata.get("schema") == "youtube-forensics.youtube-metadata/v1":
        metadata = metadata.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError("YouTube metadata envelope must contain a metadata object")
    return {"job": job, "receipt": receipt, "metadata": metadata}


def _observed_post(metadata: dict[str, Any]) -> dict[str, Any]:
    description = str(metadata.get("description") or "")
    tags = normalize_tags(metadata.get("tags") or [])
    for tag in extract_tags(description):
        if tag not in tags:
            tags.append(tag)
    metrics: dict[str, int | float] = {}
    unknown_metrics = []
    for key in ("view_count", "like_count", "comment_count", "share_count", "repost_count"):
        value = metadata.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            metrics[key] = value
        else:
            unknown_metrics.append(key)
    return {
        "source_id": metadata.get("id"),
        "title": str(metadata.get("title") or ""),
        "description": description,
        "hashtags": tags,
        "metrics": metrics,
        "unknown_metrics": unknown_metrics,
    }


def reach_signal(metrics: dict[str, int | float]) -> float:
    return round(
        float(metrics.get("like_count", 0))
        + 2 * float(metrics.get("comment_count", 0))
        + 1.5 * float(metrics.get("share_count", metrics.get("repost_count", 0)))
        + 0.001 * float(metrics.get("view_count", 0)),
        6,
    )


def score_post(caption: str, tags: Iterable[Any], platform: str) -> dict[str, Any]:
    platform = platform.strip().lower()
    rule = PLATFORM_RULES.get(platform, DEFAULT_RULE)
    tags = normalize_tags(tags)
    minimum, maximum = rule["tag_range"]
    words = re.findall(r"\w+", caption.lower())
    checks = {
        "caption_present": bool(caption.strip()),
        "within_character_limit": 0 < len(caption) <= rule["max_chars"],
        "recommended_tag_count": minimum <= len(tags) <= maximum,
        "under_tag_ceiling": len(tags) <= rule["tag_ceiling"],
        "semantic_caption": len(words) >= 8 and (not tags or any(tag in words for tag in tags)),
        "call_to_action": bool(CTA_RE.search(caption)),
    }
    weights = {
        "caption_present": 10,
        "within_character_limit": 15,
        "recommended_tag_count": 25,
        "under_tag_ceiling": 15,
        "semantic_caption": 25,
        "call_to_action": 10,
    }
    score = round(sum(weights[key] for key, passed in checks.items() if passed))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"
    return {
        "platform": platform,
        "score": score,
        "grade": grade,
        "checks": checks,
        "rule": {
            "max_chars": rule["max_chars"],
            "recommended_tag_range": list(rule["tag_range"]),
            "tag_ceiling": rule["tag_ceiling"],
        },
    }


def _tag_intelligence(posts: list[dict[str, Any]], platform: str) -> dict[str, Any]:
    document_frequency: dict[str, int] = {}
    weighted_reach: dict[str, float] = {}
    for post in posts:
        tags = set(post["hashtags"])
        signal = reach_signal(post["metrics"])
        for tag in tags:
            document_frequency[tag] = document_frequency.get(tag, 0) + 1
            weighted_reach[tag] = weighted_reach.get(tag, 0.0) + signal
    rule = PLATFORM_RULES.get(platform, DEFAULT_RULE)
    maximum = rule["tag_range"][1]
    ranked = sorted(
        document_frequency,
        key=lambda tag: (
            -document_frequency[tag],
            -(weighted_reach[tag] / document_frequency[tag]),
            tag,
        ),
    )
    if not ranked:
        seed = " ".join(
            part for post in posts for part in (post["title"], post["description"])
        )
        ranked = _keywords(seed)
    return {
        "method": "document_frequency_then_mean_observed_reach",
        "corpus_items": len(posts),
        "ranked": [
            {
                "tag": tag,
                "documents": document_frequency.get(tag, 0),
                "mean_observed_reach": (
                    round(weighted_reach[tag] / document_frequency[tag], 6)
                    if document_frequency.get(tag)
                    else None
                ),
            }
            for tag in ranked
        ],
        "suggested": ranked[:maximum],
        "grounded_in_observed_tags": bool(document_frequency),
    }


def build_intelligence(
    evidence_jobs: Iterable[Path],
    *,
    platform: str,
    proposed_caption: str = "",
    proposed_tags: Iterable[Any] = (),
) -> dict[str, Any]:
    platform = platform.strip().lower()
    if not platform or not re.fullmatch(r"[a-z0-9_-]{1,32}", platform):
        raise ValueError("Platform must be a short lowercase identifier")
    evidence_jobs = list(evidence_jobs)
    if not evidence_jobs:
        raise ValueError("At least one verified evidence package is required")
    if len(evidence_jobs) > 1000:
        raise ValueError("At most 1000 evidence packages may be compared at once")
    loaded = [_load_verified_job(Path(job)) for job in evidence_jobs]
    posts = [_observed_post(item["metadata"]) for item in loaded]
    source_receipts = sorted(
        {
            item["receipt"]["receipt_sha256"]
            for item in loaded
            if isinstance(item["receipt"].get("receipt_sha256"), str)
        }
    )
    if len(source_receipts) != len(loaded):
        raise ValueError("Every evidence package must have a distinct receipt")
    artifact = {
        "schema": INTELLIGENCE_SCHEMA,
        "status": "INTELLIGENCE_READY_REVIEW_REQUIRED",
        "platform": platform,
        "source_receipts": source_receipts,
        "engine": {
            "name": "ARGUS Amplify",
            "ruleset": RULESET_VERSION,
            "implementation_sha256": sha256_file(Path(__file__)),
        },
        "observations": posts,
        "tag_intelligence": _tag_intelligence(posts, platform),
        "proposed_post": {
            "caption": proposed_caption,
            "hashtags": normalize_tags(proposed_tags),
            "assessment": score_post(proposed_caption, proposed_tags, platform),
        },
        "limitations": [
            "Recommendations are derived interpretations, not source evidence.",
            "Missing engagement fields remain unknown and are never estimated.",
            "This artifact is not authority to publish or spend money.",
        ],
    }
    artifact["artifact_sha256"] = sha256_bytes(canonical(artifact))
    return artifact


def build_feedback(
    intelligence: dict[str, Any],
    *,
    metrics: dict[str, int | float],
) -> dict[str, Any]:
    if intelligence.get("schema") != INTELLIGENCE_SCHEMA:
        raise ValueError("Unsupported intelligence artifact")
    body = dict(intelligence)
    expected = body.pop("artifact_sha256", None)
    if expected != sha256_bytes(canonical(body)):
        raise ValueError("Intelligence artifact hash mismatch")
    allowed = {"view_count", "like_count", "comment_count", "share_count", "repost_count"}
    if not metrics or set(metrics) - allowed:
        raise ValueError("Feedback has unknown or missing metric fields")
    normalized: dict[str, int | float] = {}
    for key, value in metrics.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"Invalid feedback metric: {key}")
        normalized[key] = value
    feedback = {
        "schema": FEEDBACK_SCHEMA,
        "status": "OBSERVED_PERFORMANCE_FEEDBACK",
        "intelligence_sha256": intelligence["artifact_sha256"],
        "source_receipts": intelligence["source_receipts"],
        "platform": intelligence["platform"],
        "metrics": normalized,
        "reach_signal": reach_signal(normalized),
        "limitations": [
            "Metrics are caller-supplied observations and require source custody.",
            "Feedback appends learning evidence; it does not rewrite original evidence.",
        ],
    }
    feedback["feedback_sha256"] = sha256_bytes(canonical(feedback))
    return feedback

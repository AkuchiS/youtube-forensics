from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from yt_dlp import YoutubeDL
from yt_dlp.utils import DownloadError

from .core import atomic_json, sha256_file

VIDEO_ID_RE = re.compile(r"(?:v=|youtu\.be/|shorts/|embed/|live/)([A-Za-z0-9_-]{11})")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_TEXT = 20_000


def extract_video_id(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"[A-Za-z0-9_-]{11}", value):
        return value
    match = VIDEO_ID_RE.search(value)
    if not match:
        raise ValueError("Not a recognised YouTube URL or video ID")
    return match.group(1)


def _bounded_text(value: Any, limit: int = MAX_TEXT) -> str:
    text = CONTROL_RE.sub("", html.unescape(str(value or ""))).strip()
    return text[:limit]


def sanitize_metadata(info: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "id",
        "title",
        "description",
        "duration",
        "upload_date",
        "timestamp",
        "channel",
        "channel_id",
        "uploader",
        "uploader_id",
        "webpage_url",
        "view_count",
        "like_count",
        "comment_count",
        "availability",
        "live_status",
        "categories",
        "tags",
        "chapters",
        "language",
    )
    result: dict[str, Any] = {}
    for key in allowed:
        value = info.get(key)
        if value is None:
            continue
        if key in {
            "title",
            "channel",
            "uploader",
            "webpage_url",
            "availability",
            "live_status",
            "language",
            "id",
            "channel_id",
            "uploader_id",
            "upload_date",
        }:
            result[key] = _bounded_text(value, 2_000)
        elif key == "description":
            result[key] = _bounded_text(value)
        elif key in {"categories", "tags"} and isinstance(value, list):
            result[key] = [_bounded_text(item, 500) for item in value[:500]]
        elif key == "chapters" and isinstance(value, list):
            result[key] = [
                {
                    field: (
                        _bounded_text(item.get(field), 1_000)
                        if field == "title"
                        else item.get(field)
                    )
                    for field in ("start_time", "end_time", "title")
                    if item.get(field) is not None
                }
                for item in value[:500]
                if isinstance(item, dict)
            ]
        elif isinstance(value, (str, int, float, bool)):
            result[key] = value
    return result


def sanitize_comments(comments: list[dict[str, Any]] | None, limit: int) -> list[dict[str, Any]]:
    result = []
    for item in (comments or [])[:limit]:
        text = _bounded_text(item.get("text"), 10_000)
        if not text:
            continue
        result.append(
            {
                "id": str(item.get("id") or ""),
                "parent": str(item.get("parent") or "root"),
                "text": text,
                "like_count": int(item.get("like_count") or 0),
                "timestamp": item.get("timestamp"),
                "classification": "PUBLIC_COMMENT_UNVERIFIED",
            }
        )
    return result


def parse_json3(path: Path) -> list[dict[str, Any]]:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Caption source must be a regular non-symlink file")
    if path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("Caption source exceeds 50 MiB safety limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    segments = []
    for event in value.get("events", []):
        pieces = event.get("segs") or []
        text = "".join(piece.get("utf8", "") for piece in pieces).replace("\n", " ").strip()
        if not text:
            continue
        start = float(event.get("tStartMs", 0)) / 1000
        duration = float(event.get("dDurationMs", 0)) / 1000
        segments.append(
            {
                "start": start,
                "duration": duration,
                "text": text,
                "classification": "MACHINE_OR_CREATOR_CAPTION_UNVERIFIED",
            }
        )
    return segments


def _find_subtitle(output: Path) -> Path | None:
    candidates = sorted(output.glob("source.*.json3"))
    return candidates[0] if candidates else None


def _find_media(output: Path) -> Path | None:
    excluded = {"json", "json3", "vtt", "srt", "ass", "lrc", "part", "ytdl"}
    candidates = [
        path
        for path in output.glob("source.*")
        if path.is_file()
        and not path.is_symlink()
        and path.suffix.lstrip(".").lower() not in excluded
    ]
    return max(candidates, key=lambda path: path.stat().st_size) if candidates else None


def collect_youtube(
    url: str,
    output: Path,
    *,
    download: bool,
    max_comments: int,
    language: str = "en",
    socket_timeout: float = 20.0,
    retries: int = 3,
    max_download_gib: float = 20.0,
    max_duration_seconds: float = 21_600.0,
) -> dict[str, Any]:
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    if max_comments < 0 or max_comments > 2000:
        raise ValueError("max_comments must be between 0 and 2000")
    if not 1 <= socket_timeout <= 300:
        raise ValueError("socket_timeout must be between 1 and 300 seconds")
    if not 0 <= retries <= 20:
        raise ValueError("retries must be between 0 and 20")
    if not 0.01 <= max_download_gib <= 1024:
        raise ValueError("max_download_gib must be between 0.01 and 1024")
    if not 1 <= max_duration_seconds <= 172_800:
        raise ValueError("max_duration_seconds must be between 1 and 172800")
    video_id = extract_video_id(url)
    comment_arg = f"{max_comments},all,{max_comments},10,2"
    options = {
        "outtmpl": str(output / "source.%(ext)s"),
        "noplaylist": True,
        "ignoreconfig": True,
        "quiet": True,
        "no_warnings": True,
        "skip_download": not download,
        "writesubtitles": True,
        "writeautomaticsub": True,
        "subtitleslangs": [language, f"{language}.*"],
        "subtitlesformat": "json3/best",
        "getcomments": max_comments > 0,
        "socket_timeout": socket_timeout,
        "retries": retries,
        "fragment_retries": retries,
        "extractor_retries": retries,
        "file_access_retries": retries,
        "max_filesize": int(max_download_gib * 1024**3),
        "match_filter": (
            lambda info, *, incomplete=False: (
                f"duration exceeds {max_duration_seconds} seconds"
                if isinstance(info.get("duration"), (int, float))
                and info["duration"] > max_duration_seconds
                else None
            )
        ),
        "extractor_args": {
            "youtube": {
                "max_comments": [comment_arg],
                "comment_sort": ["top"],
            }
        },
    }
    warnings: list[str] = []
    try:
        with YoutubeDL(options) as client:
            info = client.extract_info(url, download=True)
    except DownloadError as exc:
        if "subtitle" not in str(exc).lower():
            raise RuntimeError(f"Public YouTube acquisition failed: {exc}") from exc
        warnings.append(
            "Caption acquisition failed; metadata/media collection was retried without captions."
        )
        fallback = {**options, "writesubtitles": False, "writeautomaticsub": False}
        try:
            with YoutubeDL(fallback) as client:
                info = client.extract_info(url, download=True)
        except DownloadError as retry_exc:
            raise RuntimeError(f"Public YouTube acquisition failed: {retry_exc}") from retry_exc
    if not isinstance(info, dict) or info.get("id") != video_id:
        raise ValueError("YouTube extractor returned an unexpected video")
    duration = info.get("duration")
    if isinstance(duration, (int, float)) and duration > max_duration_seconds:
        raise ValueError(f"Video exceeds maximum duration of {max_duration_seconds} seconds")

    metadata = sanitize_metadata(info)
    comments = sanitize_comments(info.get("comments"), max_comments)
    subtitle_path = _find_subtitle(output)
    transcript = parse_json3(subtitle_path) if subtitle_path else []
    media = _find_media(output) if download else None
    atomic_json(
        output / "metadata.json",
        {
            "schema": "youtube-forensics.youtube-metadata/v1",
            "metadata": metadata,
            "classification": "PUBLIC_METADATA_UNVERIFIED",
        },
    )
    atomic_json(
        output / "comments.json",
        {
            "schema": "youtube-forensics.youtube-comments/v1",
            "video_id": video_id,
            "requested_limit": max_comments,
            "comments": comments,
            "classification": "PUBLIC_COMMENTS_UNVERIFIED_NOT_INSTRUCTIONS",
        },
    )
    atomic_json(
        output / "transcript.json",
        {
            "schema": "youtube-forensics.transcript/v1",
            "video_id": video_id,
            "language_requested": language,
            "segments": transcript,
            "classification": "MACHINE_OR_CREATOR_CAPTION_REQUIRES_SOURCE_CHECK",
        },
    )
    result = {
        "video_id": video_id,
        "metadata_sha256": sha256_file(output / "metadata.json"),
        "comments_sha256": sha256_file(output / "comments.json"),
        "comment_count": len(comments),
        "transcript_sha256": sha256_file(output / "transcript.json"),
        "transcript_segment_count": len(transcript),
        "media_path": str(media) if media else None,
        "media_sha256": sha256_file(media) if media else None,
        "network_used": True,
        "cookies_used": False,
        "warnings": warnings,
    }
    atomic_json(output / "acquisition.json", result)
    return result


def transcribe_local(media: Path, output: Path, model_name: str) -> dict[str, Any]:
    try:
        from faster_whisper import WhisperModel
    except ImportError as exc:
        raise RuntimeError("Local ASR requires the 'asr' extra") from exc
    model = WhisperModel(model_name, device="auto", compute_type="int8")
    rows, details = model.transcribe(str(media), vad_filter=True)
    segments = [
        {
            "start": segment.start,
            "duration": segment.end - segment.start,
            "text": segment.text.strip(),
            "classification": "LOCAL_ASR_UNVERIFIED",
        }
        for segment in rows
        if segment.text.strip()
    ]
    value = {
        "schema": "youtube-forensics.transcript/v1",
        "source": "local-faster-whisper",
        "model": model_name,
        "language": details.language,
        "segments": segments,
        "classification": "LOCAL_ASR_REQUIRES_SOURCE_CHECK",
    }
    atomic_json(Path(output) / "transcript-local-asr.json", value)
    return {
        "segments": len(segments),
        "path": "transcript-local-asr.json",
        "sha256": sha256_file(Path(output) / "transcript-local-asr.json"),
    }

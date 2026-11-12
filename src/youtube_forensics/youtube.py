from __future__ import annotations

import html
import json
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from yt_dlp import YoutubeDL
from yt_dlp.utils import DownloadError

from .core import atomic_json, sha256_file

VIDEO_ID_RE = re.compile(r"[A-Za-z0-9_-]{11}")
YOUTUBE_HOSTS = {
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "youtu.be",
    "youtube-nocookie.com",
    "www.youtube-nocookie.com",
}
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_TEXT = 20_000
MAX_TRANSCRIPT_SEGMENTS = 100_000


def extract_video_id(value: str) -> str:
    value = value.strip()
    if VIDEO_ID_RE.fullmatch(value):
        return value
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or host not in YOUTUBE_HOSTS:
        raise ValueError("Not a recognised YouTube URL or video ID")
    candidate = ""
    if host == "youtu.be":
        candidate = parsed.path.strip("/").split("/", 1)[0]
    else:
        pieces = [piece for piece in parsed.path.split("/") if piece]
        if pieces and pieces[0] in {"shorts", "embed", "live"} and len(pieces) > 1:
            candidate = pieces[1]
        else:
            candidate = parse_qs(parsed.query).get("v", [""])[0]
    if not VIDEO_ID_RE.fullmatch(candidate):
        raise ValueError("Not a recognised YouTube URL or video ID")
    return candidate


def canonical_youtube_url(value: str) -> str:
    return f"https://www.youtube.com/watch?v={extract_video_id(value)}"


def _bounded_text(value: Any, limit: int = MAX_TEXT) -> str:
    text = CONTROL_RE.sub("", html.unescape(str(value or ""))).strip()
    return text[:limit]


def _bounded_fragment(value: Any, limit: int = MAX_TEXT) -> str:
    """Sanitize a caption fragment without removing meaningful edge spaces."""
    return CONTROL_RE.sub("", html.unescape(str(value or "")))[:limit]


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
            chapters = []
            for item in value[:500]:
                if not isinstance(item, dict):
                    continue
                chapter: dict[str, Any] = {}
                for field in ("start_time", "end_time"):
                    number = item.get(field)
                    if isinstance(number, (int, float)) and math.isfinite(number):
                        chapter[field] = number
                if item.get("title") is not None:
                    chapter["title"] = _bounded_text(item["title"], 1_000)
                chapters.append(chapter)
            result[key] = chapters
        elif isinstance(value, str):
            result[key] = _bounded_text(value)
        elif isinstance(value, (int, float, bool)) and (
            not isinstance(value, float) or math.isfinite(value)
        ):
            result[key] = value
    return result


def sanitize_comments(comments: list[dict[str, Any]] | None, limit: int) -> list[dict[str, Any]]:
    result = []
    for item in (comments or [])[:limit]:
        if not isinstance(item, dict):
            continue
        text = _bounded_text(item.get("text"), 10_000)
        if not text:
            continue
        try:
            like_count = max(0, int(item.get("like_count") or 0))
        except (TypeError, ValueError, OverflowError):
            like_count = 0
        result.append(
            {
                "id": _bounded_text(item.get("id"), 500),
                "parent": _bounded_text(item.get("parent") or "root", 500),
                "text": text,
                "like_count": like_count,
                "timestamp": (
                    item.get("timestamp")
                    if isinstance(item.get("timestamp"), (int, float))
                    and math.isfinite(item["timestamp"])
                    else None
                ),
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
    if not isinstance(value, dict) or not isinstance(value.get("events", []), list):
        raise ValueError("Caption source has an invalid JSON3 shape")
    segments = []
    for event in value.get("events", [])[:MAX_TRANSCRIPT_SEGMENTS]:
        if not isinstance(event, dict):
            continue
        pieces = event.get("segs") or []
        if not isinstance(pieces, list):
            continue
        text = (
            "".join(
                _bounded_fragment(piece.get("utf8", ""), 10_000)
                for piece in pieces[:2_000]
                if isinstance(piece, dict)
            )
            .replace("\n", " ")
            .strip()
        )
        if not text:
            continue
        try:
            start_ms = float(event.get("tStartMs", 0))
            duration_ms = float(event.get("dDurationMs", 0))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(start_ms) or not math.isfinite(duration_ms):
            continue
        start = start_ms / 1000
        duration = duration_ms / 1000
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
    url = canonical_youtube_url(video_id)
    max_download_bytes = int(max_download_gib * 1024**3)

    def reject_unbounded(info: dict[str, Any], *, incomplete: bool = False) -> str | None:
        del incomplete
        if info.get("is_live") is True or info.get("live_status") in {
            "is_live",
            "is_upcoming",
        }:
            return "live and upcoming streams are not supported"
        duration = info.get("duration")
        if download and (not isinstance(duration, (int, float)) or not math.isfinite(duration)):
            return "download requires a finite reported duration"
        if isinstance(duration, (int, float)) and duration > max_duration_seconds:
            return f"duration exceeds {max_duration_seconds} seconds"
        return None

    downloaded_by_target: dict[str, int] = {}

    def enforce_download_size(status: dict[str, Any]) -> None:
        observed = max(
            int(status.get("downloaded_bytes") or 0),
            int(status.get("total_bytes") or 0),
            int(status.get("total_bytes_estimate") or 0),
        )
        target = _bounded_text(
            status.get("filename") or status.get("tmpfilename") or "unknown", 4_096
        )
        downloaded_by_target[target] = max(downloaded_by_target.get(target, 0), observed)
        if sum(downloaded_by_target.values()) > max_download_bytes:
            raise DownloadError(f"download exceeds {max_download_gib} GiB limit")

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
        "max_filesize": max_download_bytes,
        "progress_hooks": [enforce_download_size],
        "match_filter": reject_unbounded,
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
    rejection = reject_unbounded(info)
    if rejection:
        raise ValueError(rejection)
    if isinstance(duration, (int, float)) and duration > max_duration_seconds:
        raise ValueError(f"Video exceeds maximum duration of {max_duration_seconds} seconds")

    metadata = sanitize_metadata(info)
    comments = sanitize_comments(info.get("comments"), max_comments)
    subtitle_path = _find_subtitle(output)
    transcript = parse_json3(subtitle_path) if subtitle_path else []
    media = _find_media(output) if download else None
    if media and media.stat().st_size > max_download_bytes:
        raise ValueError(f"Downloaded media exceeds {max_download_gib} GiB limit")
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
        "media_path": media.relative_to(output).as_posix() if media else None,
        "media_sha256": sha256_file(media) if media else None,
        "network_used": True,
        "cookies_used": False,
        "warnings": warnings,
    }
    atomic_json(output / "acquisition.json", result)
    return result


def transcribe_local(
    media: Path,
    output: Path,
    model_name: str,
    *,
    allow_model_download: bool = False,
) -> dict[str, Any]:
    try:
        from faster_whisper import WhisperModel
    except ImportError as exc:
        raise RuntimeError("Local ASR requires the 'asr' extra") from exc
    model = WhisperModel(
        model_name,
        device="auto",
        compute_type="int8",
        local_files_only=not allow_model_download,
    )
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
    model_path = Path(model_name).expanduser()
    model_label = model_path.name if model_path.is_absolute() or model_path.exists() else model_name
    value = {
        "schema": "youtube-forensics.transcript/v1",
        "source": "local-faster-whisper",
        "model": model_label,
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

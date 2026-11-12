from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest
from yt_dlp.utils import DownloadError

import youtube_forensics.youtube as youtube


@pytest.mark.parametrize(
    "value",
    [
        "https://www.youtube.com/watch?v=bc7QaDmLmoA",
        "https://youtu.be/bc7QaDmLmoA?t=3",
        "https://www.youtube.com/shorts/bc7QaDmLmoA",
        "https://www.youtube.com/embed/bc7QaDmLmoA",
        "https://www.youtube.com/live/bc7QaDmLmoA",
    ],
)
def test_extract_video_id_variants(value: str) -> None:
    assert youtube.extract_video_id(value) == "bc7QaDmLmoA"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not youtube",
        "abc",
        "https://example.com/x",
        "https://internal.example/watch?v=bc7QaDmLmoA",
        "file:///tmp/watch?v=bc7QaDmLmoA",
        "https://www.youtube.com/watch?v=short",
    ],
)
def test_extract_video_id_rejects_invalid(value: str) -> None:
    with pytest.raises(ValueError):
        youtube.extract_video_id(value)


def test_canonical_youtube_url_drops_untrusted_url_components() -> None:
    assert (
        youtube.canonical_youtube_url("https://youtu.be/bc7QaDmLmoA?t=3#fragment")
        == "https://www.youtube.com/watch?v=bc7QaDmLmoA"
    )


def test_metadata_is_bounded_and_control_characters_removed() -> None:
    result = youtube.sanitize_metadata(
        {
            "title": "hello\x00world",
            "description": "x" * 30_000,
            "tags": ["a"] * 600,
            "chapters": [{"title": "chapter\x01", "start_time": 0}] * 600,
            "private": "must not pass",
        }
    )
    assert result["title"] == "helloworld"
    assert len(result["description"]) == 20_000
    assert len(result["tags"]) == 500
    assert len(result["chapters"]) == 500
    assert "private" not in result


def test_comments_are_bounded_sanitized_and_deidentified() -> None:
    rows = youtube.sanitize_comments(
        [
            {"id": "1", "text": "a\x00b" + "x" * 20_000, "author": "secret"},
            {"id": "2", "text": "second"},
        ],
        1,
    )
    assert len(rows) == 1
    assert rows[0]["text"].startswith("ab")
    assert len(rows[0]["text"]) == 10_000
    assert "author" not in rows[0]


def test_comments_tolerate_hostile_scalar_fields() -> None:
    rows = youtube.sanitize_comments(
        [None, {"id": "x\x00" * 600, "text": "safe", "like_count": "not-a-number"}],
        2,
    )
    assert len(rows) == 1
    assert len(rows[0]["id"]) == 500
    assert "\x00" not in rows[0]["id"]
    assert rows[0]["like_count"] == 0


def test_parse_json3_ignores_empty_events(tmp_path: Path) -> None:
    path = tmp_path / "captions.json3"
    path.write_text(
        json.dumps(
            {
                "events": [
                    {"tStartMs": 10, "dDurationMs": 20, "segs": [{"utf8": " hi\nthere "}]},
                    {"segs": []},
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = youtube.parse_json3(path)
    assert rows[0]["start"] == 0.01
    assert rows[0]["duration"] == 0.02
    assert rows[0]["text"] == "hi there"


def test_parse_json3_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json3"
    target.write_text('{"events": []}', encoding="utf-8")
    link = tmp_path / "link.json3"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        youtube.parse_json3(link)


@pytest.mark.parametrize("value", [[], {"events": "not-a-list"}])
def test_parse_json3_rejects_invalid_shape(tmp_path: Path, value) -> None:
    path = tmp_path / "captions.json3"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON3 shape"):
        youtube.parse_json3(path)


@pytest.mark.parametrize("timestamp", [None, "invalid", float("inf")])
def test_parse_json3_skips_non_numeric_timestamps(tmp_path: Path, timestamp) -> None:
    path = tmp_path / "captions.json3"
    path.write_text(
        json.dumps({"events": [{"tStartMs": timestamp, "segs": [{"utf8": "unsafe"}]}]}),
        encoding="utf-8",
    )
    assert youtube.parse_json3(path) == []


def test_parse_json3_caps_transcript_segments(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(youtube, "MAX_TRANSCRIPT_SEGMENTS", 2)
    path = tmp_path / "captions.json3"
    path.write_text(
        json.dumps(
            {
                "events": [
                    {"tStartMs": index, "segs": [{"utf8": f"row {index}"}]} for index in range(5)
                ]
            }
        ),
        encoding="utf-8",
    )
    assert len(youtube.parse_json3(path)) == 2


class FakeYoutubeDL:
    calls: list[dict] = []
    urls: list[str] = []
    fail_first_caption = False

    def __init__(self, options: dict) -> None:
        self.options = options
        self.__class__.calls.append(options)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def extract_info(self, _url: str, *, download: bool):
        self.__class__.urls.append(_url)
        if self.__class__.fail_first_caption and self.options.get("writesubtitles"):
            raise DownloadError("subtitle endpoint unavailable")
        output = Path(self.options["outtmpl"]).parent
        if self.options.get("writesubtitles"):
            (output / "source.en.json3").write_text(
                json.dumps({"events": [{"tStartMs": 0, "segs": [{"utf8": "caption"}]}]}),
                encoding="utf-8",
            )
        return {
            "id": "bc7QaDmLmoA",
            "title": "Public demo",
            "duration": 30,
            "comments": [{"id": "1", "text": "comment", "author": "removed"}],
        }


def test_collect_youtube_applies_network_bounds(monkeypatch, tmp_path: Path) -> None:
    FakeYoutubeDL.calls = []
    FakeYoutubeDL.urls = []
    FakeYoutubeDL.fail_first_caption = False
    monkeypatch.setattr(youtube, "YoutubeDL", FakeYoutubeDL)
    result = youtube.collect_youtube(
        "bc7QaDmLmoA",
        tmp_path,
        download=False,
        max_comments=1,
        socket_timeout=7,
        retries=2,
        max_download_gib=1,
        max_duration_seconds=60,
    )
    assert result["video_id"] == "bc7QaDmLmoA"
    assert result["transcript_segment_count"] == 1
    options = FakeYoutubeDL.calls[0]
    assert options["socket_timeout"] == 7
    assert options["retries"] == 2
    assert options["fragment_retries"] == 2
    assert options["max_filesize"] == 1024**3
    assert len(options["progress_hooks"]) == 1
    assert FakeYoutubeDL.urls == ["https://www.youtube.com/watch?v=bc7QaDmLmoA"]
    comments = json.loads((tmp_path / "comments.json").read_text())
    assert "author" not in comments["comments"][0]


def test_collect_youtube_caption_failure_has_bounded_fallback(monkeypatch, tmp_path: Path) -> None:
    FakeYoutubeDL.calls = []
    FakeYoutubeDL.fail_first_caption = True
    monkeypatch.setattr(youtube, "YoutubeDL", FakeYoutubeDL)
    result = youtube.collect_youtube("bc7QaDmLmoA", tmp_path, download=False, max_comments=0)
    assert len(FakeYoutubeDL.calls) == 2
    assert result["warnings"]
    assert result["transcript_segment_count"] == 0


@pytest.mark.parametrize(
    "fields, message",
    [
        ({"is_live": True, "live_status": "is_live", "duration": None}, "live"),
        ({"live_status": "is_upcoming", "duration": None}, "live"),
        ({"live_status": "not_live", "duration": None}, "finite"),
    ],
)
def test_download_rejects_live_or_unknown_duration(
    monkeypatch, tmp_path: Path, fields: dict, message: str
) -> None:
    class UnboundedYoutubeDL(FakeYoutubeDL):
        def extract_info(self, _url: str, *, download: bool):
            return {"id": "bc7QaDmLmoA", "title": "Unsafe", **fields}

    monkeypatch.setattr(youtube, "YoutubeDL", UnboundedYoutubeDL)
    with pytest.raises(ValueError, match=message):
        youtube.collect_youtube("bc7QaDmLmoA", tmp_path, download=True, max_comments=0)


def test_progress_hook_rejects_fragmented_oversize(monkeypatch, tmp_path: Path) -> None:
    class OversizeYoutubeDL(FakeYoutubeDL):
        def extract_info(self, _url: str, *, download: bool):
            self.options["progress_hooks"][0]({"downloaded_bytes": 2 * 1024**3})
            return {"id": "bc7QaDmLmoA", "title": "Large", "duration": 30}

    monkeypatch.setattr(youtube, "YoutubeDL", OversizeYoutubeDL)
    with pytest.raises(RuntimeError, match="exceeds"):
        youtube.collect_youtube(
            "bc7QaDmLmoA",
            tmp_path,
            download=True,
            max_comments=0,
            max_download_gib=1,
        )


def test_progress_hook_enforces_aggregate_stream_size(monkeypatch, tmp_path: Path) -> None:
    class AggregateYoutubeDL(FakeYoutubeDL):
        def extract_info(self, _url: str, *, download: bool):
            hook = self.options["progress_hooks"][0]
            hook({"filename": "video.part", "downloaded_bytes": 600 * 1024**2})
            hook({"filename": "audio.part", "downloaded_bytes": 600 * 1024**2})
            return {"id": "bc7QaDmLmoA", "title": "Large", "duration": 30}

    monkeypatch.setattr(youtube, "YoutubeDL", AggregateYoutubeDL)
    with pytest.raises(RuntimeError, match="exceeds"):
        youtube.collect_youtube(
            "bc7QaDmLmoA",
            tmp_path,
            download=True,
            max_comments=0,
            max_download_gib=1,
        )


@pytest.mark.parametrize("allow_download, local_only", [(False, True), (True, False)])
def test_local_asr_model_download_is_explicit(
    monkeypatch, tmp_path: Path, allow_download: bool, local_only: bool
) -> None:
    calls = []

    class FakeModel:
        def __init__(self, *_args, **kwargs):
            calls.append(kwargs)

        def transcribe(self, _media, *, vad_filter):
            assert vad_filter is True
            return [], types.SimpleNamespace(language="en")

    monkeypatch.setitem(
        sys.modules, "faster_whisper", types.SimpleNamespace(WhisperModel=FakeModel)
    )
    media = tmp_path / "media.mp4"
    media.write_bytes(b"owner supplied")
    result = youtube.transcribe_local(
        media,
        tmp_path,
        "small.en",
        allow_model_download=allow_download,
    )
    assert calls[0]["local_files_only"] is local_only
    assert result["segments"] == 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_comments": -1},
        {"max_comments": 2001},
        {"max_comments": 0, "socket_timeout": 0},
        {"max_comments": 0, "retries": 21},
        {"max_comments": 0, "max_download_gib": 0},
        {"max_comments": 0, "max_duration_seconds": 0},
    ],
)
def test_collect_youtube_rejects_unbounded_options(tmp_path: Path, kwargs: dict) -> None:
    with pytest.raises(ValueError):
        youtube.collect_youtube("bc7QaDmLmoA", tmp_path, download=False, **kwargs)

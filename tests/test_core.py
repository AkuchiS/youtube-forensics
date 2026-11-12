from __future__ import annotations

import json
from pathlib import Path

import av
import numpy as np

from youtube_forensics.core import analyse_local_video, build_receipt, verify_job
from youtube_forensics.youtube import extract_video_id, parse_json3, sanitize_comments


def make_video(path: Path) -> None:
    output = av.open(str(path), "w")
    stream = output.add_stream("mpeg4", rate=4)
    stream.width = 64
    stream.height = 48
    stream.pix_fmt = "yuv420p"
    for value in (0, 0, 255, 255):
        array = np.full((48, 64, 3), value, dtype=np.uint8)
        frame = av.VideoFrame.from_ndarray(array, format="rgb24")
        for packet in stream.encode(frame):
            output.mux(packet)
    for packet in stream.encode(None):
        output.mux(packet)
    output.close()


def test_video_analysis_and_tamper_detection(tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    make_video(source)
    job = tmp_path / "job"
    job.mkdir()
    result = analyse_local_video(source, job)
    assert result["source_name"] == "source.mp4"
    assert "source_path" not in result
    assert result["frame_count"] == 4
    assert result["retained_state_count"] >= 2
    receipt = build_receipt(
        job, input_value=str(source), network_used=False, acquisition=None, video=result
    )
    assert receipt["status"] == "EVIDENCE_READY_HUMAN_OR_AGENT_REVIEW_REQUIRED"
    assert verify_job(job)["verified"] is True
    (job / "video-analysis.json").write_text("tampered", encoding="utf-8")
    checked = verify_job(job)
    assert checked["verified"] is False
    assert any("video-analysis.json" in item for item in checked["problems"])


def test_youtube_id_and_comments_are_bounded() -> None:
    assert extract_video_id("bc7QaDmLmoA") == "bc7QaDmLmoA"
    assert extract_video_id("https://youtu.be/bc7QaDmLmoA") == "bc7QaDmLmoA"
    comments = sanitize_comments(
        [
            {"id": "1", "text": " First &amp; useful ", "like_count": 4, "author": "private"},
            {"id": "2", "text": "second"},
        ],
        1,
    )
    assert comments == [
        {
            "id": "1",
            "parent": "root",
            "text": "First & useful",
            "like_count": 4,
            "timestamp": None,
            "classification": "PUBLIC_COMMENT_UNVERIFIED",
        }
    ]
    assert "author" not in comments[0]


def test_json3_transcript(tmp_path: Path) -> None:
    path = tmp_path / "captions.json3"
    path.write_text(
        json.dumps(
            {
                "events": [
                    {
                        "tStartMs": 1250,
                        "dDurationMs": 500,
                        "segs": [{"utf8": "hello "}, {"utf8": "world"}],
                    },
                    {"tStartMs": 2000, "segs": [{"utf8": "\n"}]},
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = parse_json3(path)
    assert rows == [
        {
            "start": 1.25,
            "duration": 0.5,
            "text": "hello world",
            "classification": "MACHINE_OR_CREATOR_CAPTION_UNVERIFIED",
        }
    ]

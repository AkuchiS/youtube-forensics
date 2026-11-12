from __future__ import annotations

import json
from pathlib import Path

import av
import numpy as np
import pytest

import youtube_forensics.core as core
from youtube_forensics.cli import analyse, parser


def make_video(path: Path, frames: int = 8) -> None:
    output = av.open(str(path), "w")
    stream = output.add_stream("mpeg4", rate=4)
    stream.width = 64
    stream.height = 48
    stream.pix_fmt = "yuv420p"
    for index in range(frames):
        value = 255 if index % 2 else 0
        frame = av.VideoFrame.from_ndarray(
            np.full((48, 64, 3), value, dtype=np.uint8), format="rgb24"
        )
        for packet in stream.encode(frame):
            output.mux(packet)
    for packet in stream.encode(None):
        output.mux(packet)
    output.close()


def test_interrupted_analysis_resumes_without_duplicate_rows(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    job.mkdir()
    make_video(source)
    original = core._write_jpeg
    calls = 0

    def interrupt_once(frame, path, max_width=1280):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated interruption")
        return original(frame, path, max_width=max_width)

    monkeypatch.setattr(core, "_write_jpeg", interrupt_once)
    with pytest.raises(RuntimeError, match="simulated interruption"):
        core.analyse_local_video(source, job, checkpoint_interval=1)
    assert (job / ".frame-checkpoint.json").is_file()

    monkeypatch.setattr(core, "_write_jpeg", original)
    result = core.analyse_local_video(source, job, resume=True, checkpoint_interval=1)
    assert result["frame_count"] == 8
    rows = (job / "frame-index.jsonl").read_text(encoding="utf-8").splitlines()
    decoded = [json.loads(row)["frame"] for row in rows[1:-1]]
    assert decoded == list(range(8))
    assert not (job / ".frame-checkpoint.json").exists()


def test_resume_rejects_different_parameters(tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    job.mkdir()
    make_video(source, 2)
    with pytest.MonkeyPatch.context() as monkeypatch:
        original = core._write_jpeg
        calls = 0

        def stop(frame, path, max_width=1280):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("stop")
            return original(frame, path, max_width=max_width)

        monkeypatch.setattr(core, "_write_jpeg", stop)
        with pytest.raises(RuntimeError):
            core.analyse_local_video(source, job, checkpoint_interval=1)
    with pytest.raises(ValueError, match="threshold"):
        core.analyse_local_video(source, job, threshold=0.5, resume=True)


def test_cli_parser_exposes_version_and_safety_limits() -> None:
    args = parser().parse_args(
        [
            "analyse",
            "input.mp4",
            "--output",
            "job",
            "--max-source-gib",
            "3",
            "--max-duration",
            "90",
            "--network-timeout",
            "8",
            "--retries",
            "1",
        ]
    )
    assert args.max_source_gib == 3
    assert args.max_duration == 90
    assert args.network_timeout == 8
    assert args.retries == 1


def test_cli_failure_writes_structured_failure_receipt(tmp_path: Path) -> None:
    args = parser().parse_args(
        ["analyse", str(tmp_path / "missing.mp4"), "--output", str(tmp_path / "job")]
    )
    with pytest.raises(ValueError):
        analyse(args)
    failure = json.loads((tmp_path / "job" / "failure.json").read_text(encoding="utf-8"))
    assert failure["status"] == "FAILED"
    assert failure["error_type"] == "ValueError"
    assert failure["resumable"] is False

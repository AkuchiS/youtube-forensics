from __future__ import annotations

import json
import types
from pathlib import Path

import av
import numpy as np
import pytest

import youtube_forensics.cli as cli
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


def _make_interrupted_job(monkeypatch, source: Path, job: Path) -> None:
    original = core._write_jpeg
    calls = 0

    def stop(frame, path, max_width=1280):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("stop")
        return original(frame, path, max_width=max_width)

    monkeypatch.setattr(core, "_write_jpeg", stop)
    with pytest.raises(RuntimeError, match="stop"):
        core.analyse_local_video(source, job, checkpoint_interval=1)
    monkeypatch.setattr(core, "_write_jpeg", original)


def test_resume_rejects_extra_retained_frame(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    job.mkdir()
    make_video(source)
    _make_interrupted_job(monkeypatch, source, job)
    (job / "retained-frames" / "unexpected.jpg").write_bytes(b"not evidence")
    with pytest.raises(ValueError, match="unrelated artifact"):
        core.analyse_local_video(source, job, resume=True, checkpoint_interval=1)


def test_resume_removes_only_post_checkpoint_frame_artifacts(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    job.mkdir()
    make_video(source)
    _make_interrupted_job(monkeypatch, source, job)
    extra = job / "retained-frames" / "frame-00000007.jpg"
    partial = job / "retained-frames" / ".frame-00000007.partial.jpg"
    extra.write_bytes(b"post-checkpoint")
    partial.write_bytes(b"partial")
    result = core.analyse_local_video(source, job, resume=True, checkpoint_interval=1)
    assert result["frame_count"] == 8
    assert not partial.exists()


def test_resume_rejects_malformed_last_row(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    job.mkdir()
    make_video(source)
    _make_interrupted_job(monkeypatch, source, job)
    checkpoint_path = job / ".frame-checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["last_row"].pop("frame")
    core.atomic_json(checkpoint_path, checkpoint)
    with pytest.raises(ValueError, match="last row is malformed"):
        core.analyse_local_video(source, job, resume=True, checkpoint_interval=1)


def test_resume_rejects_forged_partial_index(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    job.mkdir()
    make_video(source)
    _make_interrupted_job(monkeypatch, source, job)
    partial = job / ".frame-index.partial.jsonl"
    checkpoint_path = job / ".frame-checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    lines = partial.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[-1])
    forged["perceptual_hash"] = "f" * 16
    lines[-1] = json.dumps(forged, sort_keys=True)
    partial.write_text("\n".join(lines) + "\n", encoding="utf-8")
    checkpoint["index_offset"] = partial.stat().st_size
    core.atomic_json(checkpoint_path, checkpoint)
    with pytest.raises(ValueError, match="last row does not match"):
        core.analyse_local_video(source, job, resume=True, checkpoint_interval=1)


def test_local_analysis_rejects_symlink_source(tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    make_video(source, 2)
    link = tmp_path / "link.mp4"
    link.symlink_to(source)
    job = tmp_path / "job"
    job.mkdir()
    with pytest.raises(ValueError, match="non-symlink"):
        core.analyse_local_video(link, job)


def test_cli_rejects_symlink_source(tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    make_video(source, 2)
    link = tmp_path / "link.mp4"
    link.symlink_to(source)
    args = parser().parse_args(["analyse", str(link), "--output", str(tmp_path / "job")])
    with pytest.raises(ValueError, match="must not be a symlink"):
        analyse(args)


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
    missing = tmp_path / "private" / "missing.mp4"
    args = parser().parse_args(["analyse", str(missing), "--output", str(tmp_path / "job")])
    with pytest.raises(ValueError):
        analyse(args)
    failure = json.loads((tmp_path / "job" / "failure.json").read_text(encoding="utf-8"))
    assert failure["status"] == "FAILED"
    assert failure["error_type"] == "ValueError"
    assert failure["resumable"] is False
    serialized = json.dumps(failure)
    assert str(tmp_path) not in serialized
    assert failure["input"] == "missing.mp4"


def test_cli_never_fetches_non_youtube_url(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        cli,
        "collect_youtube",
        lambda *_args, **_kwargs: pytest.fail("non-YouTube URL reached network collector"),
    )
    args = parser().parse_args(
        ["analyse", "https://example.com/video", "--output", str(tmp_path / "job")]
    )
    with pytest.raises(ValueError, match="neither a URL nor a file"):
        analyse(args)


def test_resume_removes_only_known_atomic_write_temps(tmp_path: Path) -> None:
    job = tmp_path / "job"
    job.mkdir()
    (job / ".frame-index.partial.jsonl").write_text("{}\n", encoding="utf-8")
    (job / ".frame-checkpoint.json").write_text("{}\n", encoding="utf-8")
    (job / ".frame-checkpoint.json.interrupted.tmp").write_text("partial", encoding="utf-8")
    assert core.prepare_output(job, resume=True) == job.resolve()
    assert not (job / ".frame-checkpoint.json.interrupted.tmp").exists()


@pytest.mark.parametrize("allow_download, expected_network", [(False, False), (True, True)])
def test_cli_records_explicit_asr_model_network_permission(
    monkeypatch, tmp_path: Path, allow_download: bool, expected_network: bool
) -> None:
    source = tmp_path / "source.mp4"
    source.write_bytes(b"owner supplied")
    job = tmp_path / "job"
    monkeypatch.setattr(cli, "analyse_local_video", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(cli, "transcribe_local", lambda *_args, **_kwargs: {"segments": 0})
    arguments = ["analyse", str(source), "--output", str(job), "--local-asr"]
    if allow_download:
        arguments.append("--allow-asr-model-download")
    assert analyse(parser().parse_args(arguments)) == 0
    receipt = json.loads((job / "receipt.json").read_text(encoding="utf-8"))
    assert receipt["network_used"] is expected_network


def test_remote_download_reserves_source_ceiling_before_network(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        cli.shutil,
        "disk_usage",
        lambda _path: types.SimpleNamespace(free=10 * 1024**3),
    )
    called = False

    def forbidden_collect(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(cli, "collect_youtube", forbidden_collect)
    args = parser().parse_args(
        [
            "analyse",
            "bc7QaDmLmoA",
            "--output",
            str(tmp_path / "job"),
            "--download",
            "--max-source-gib",
            "9",
            "--min-free-gib",
            "2",
        ]
    )
    with pytest.raises(RuntimeError, match="11.00 GiB is required"):
        analyse(args)
    assert called is False


def test_frame_analysis_enforces_free_space_reserve(tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    make_video(source, 2)
    job = tmp_path / "job"
    job.mkdir()
    with pytest.raises(RuntimeError, match="Free-space reserve"):
        core.analyse_local_video(source, job, min_free_bytes=10**30)


def test_successful_resume_removes_prior_failure_marker(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "source.mp4"
    job = tmp_path / "job"
    make_video(source)
    original = core._write_jpeg
    calls = 0

    def stop(frame, path, max_width=1280):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("stop")
        return original(frame, path, max_width=max_width)

    monkeypatch.setattr(core, "_write_jpeg", stop)
    initial = parser().parse_args(
        [
            "analyse",
            str(source),
            "--output",
            str(job),
            "--checkpoint-interval",
            "1",
        ]
    )
    with pytest.raises(RuntimeError, match="stop"):
        analyse(initial)
    assert (job / "failure.json").is_file()

    monkeypatch.setattr(core, "_write_jpeg", original)
    resumed = parser().parse_args(
        [
            "analyse",
            str(source),
            "--output",
            str(job),
            "--resume",
            "--checkpoint-interval",
            "1",
        ]
    )
    assert analyse(resumed) == 0
    assert not (job / "failure.json").exists()
    assert "failure.json" not in json.loads((job / "receipt.json").read_text())["files"]

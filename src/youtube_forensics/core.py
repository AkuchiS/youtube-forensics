from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any

import av


SCHEMA_VERSION = "youtube-forensics/v1"
CLAIM_CLASSES = ("OBSERVED", "DOCUMENTED", "INFERRED", "REPRODUCED", "UNKNOWN")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.",
                                     suffix=".tmp", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(canonical(value) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def ensure_new_output(path: Path) -> Path:
    path = Path(path).expanduser().resolve()
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"Output must be absent or empty: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _gray_pixels(frame: av.VideoFrame) -> list[list[int]]:
    small = frame.reformat(width=9, height=8, format="gray")
    plane = small.planes[0]
    raw = bytes(plane)
    stride = plane.line_size
    return [list(raw[row * stride:row * stride + 9]) for row in range(8)]


def frame_dhash(frame: av.VideoFrame) -> str:
    pixels = _gray_pixels(frame)
    value = 0
    for row in pixels:
        for left, right in zip(row, row[1:]):
            value = (value << 1) | int(left > right)
    return f"{value:016x}"


def hamming_score(left: str, right: str) -> float:
    return (int(left, 16) ^ int(right, 16)).bit_count() / 64.0


def _write_jpeg(frame: av.VideoFrame, path: Path, max_width: int = 1280) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    width = min(frame.width, max_width)
    height = max(2, round(frame.height * width / frame.width))
    width -= width % 2
    height -= height % 2
    converted = frame.reformat(width=width, height=height, format="yuvj420p")
    temporary = path.with_name(f".{path.stem}.partial.jpg")
    output = av.open(str(temporary), "w", format="image2")
    stream = output.add_stream("mjpeg")
    stream.width = width
    stream.height = height
    stream.pix_fmt = "yuvj420p"
    for packet in stream.encode(converted):
        output.mux(packet)
    for packet in stream.encode(None):
        output.mux(packet)
    output.close()
    os.replace(temporary, path)


def _frame_seconds(frame: av.VideoFrame, index: int, average_rate: float | None) -> tuple[float, bool]:
    if frame.pts is not None and frame.time_base is not None:
        value = float(frame.pts * frame.time_base)
        if math.isfinite(value) and value >= 0:
            return value, False
    if average_rate and average_rate > 0:
        return index / average_rate, True
    return float(index), True


def analyse_local_video(source: Path, output: Path, *, threshold: float = 0.18,
                        minimum_gap_seconds: float = 0.35) -> dict[str, Any]:
    source = Path(source).expanduser().resolve()
    if not source.is_file() or source.is_symlink():
        raise ValueError("Source must be a regular non-symlink file")
    if not 0 <= threshold <= 1 or minimum_gap_seconds < 0:
        raise ValueError("Invalid state-retention parameters")

    output = Path(output)
    frames_dir = output / "retained-frames"
    frames_dir.mkdir(parents=True, exist_ok=True)
    source_before = source.stat()
    source_digest = sha256_file(source)
    index_partial = output / ".frame-index.partial.jsonl"
    index_final = output / "frame-index.jsonl"

    retained: list[dict[str, Any]] = []
    previous_hash: str | None = None
    last_retained_seconds = -1.0
    last_frame: av.VideoFrame | None = None
    last_row: dict[str, Any] | None = None
    inferred_pts_count = 0

    container = av.open(str(source))
    streams = [stream for stream in container.streams if stream.type == "video"]
    if not streams:
        container.close()
        raise ValueError("Source has no video stream")
    stream = streams[0]
    average_rate = float(stream.average_rate) if stream.average_rate else None
    metadata = {
        "schema": "youtube-forensics.frame-index/v1",
        "source_path": str(source),
        "source_sha256": source_digest,
        "source_bytes": source_before.st_size,
        "video_stream": {
            "codec": stream.codec_context.name,
            "width": stream.codec_context.width,
            "height": stream.codec_context.height,
            "average_rate": average_rate,
        },
        "threshold": threshold,
        "minimum_gap_seconds": minimum_gap_seconds,
        "complete": False,
    }

    with index_partial.open("x", encoding="utf-8") as index_handle:
        index_handle.write(json.dumps(metadata, sort_keys=True) + "\n")
        for index, frame in enumerate(container.decode(stream)):
            seconds, inferred = _frame_seconds(frame, index, average_rate)
            inferred_pts_count += int(inferred)
            digest = frame_dhash(frame)
            change = 0.0 if previous_hash is None else hamming_score(previous_hash, digest)
            row = {
                "frame": index,
                "pts_seconds": round(seconds, 6),
                "pts_inferred": inferred,
                "perceptual_hash": digest,
                "change_score": round(change, 6),
            }
            index_handle.write(json.dumps(row, sort_keys=True) + "\n")
            should_retain = (index == 0 or
                (change >= threshold and seconds - last_retained_seconds >= minimum_gap_seconds))
            if should_retain:
                image_name = f"frame-{index:08d}.jpg"
                _write_jpeg(frame, frames_dir / image_name)
                retained.append({**row, "image": f"retained-frames/{image_name}"})
                last_retained_seconds = seconds
            previous_hash = digest
            last_frame = frame
            last_row = row

        if last_row is None or last_frame is None:
            raise ValueError("Decoder returned no video frames")
        if retained[-1]["frame"] != last_row["frame"]:
            image_name = f"frame-{last_row['frame']:08d}.jpg"
            _write_jpeg(last_frame, frames_dir / image_name)
            retained.append({**last_row, "image": f"retained-frames/{image_name}"})
        completion = {
            "schema": "youtube-forensics.frame-index-completion/v1",
            "complete": True,
            "reader_status": "completed",
            "frame_count": last_row["frame"] + 1,
            "last_pts_seconds": last_row["pts_seconds"],
            "inferred_pts_count": inferred_pts_count,
        }
        index_handle.write(json.dumps(completion, sort_keys=True) + "\n")
        index_handle.flush()
        os.fsync(index_handle.fileno())
    container.close()

    source_after = source.stat()
    if (source_before.st_dev, source_before.st_ino, source_before.st_size, source_before.st_mtime_ns) != (
            source_after.st_dev, source_after.st_ino, source_after.st_size, source_after.st_mtime_ns):
        index_partial.unlink(missing_ok=True)
        raise ValueError("Source changed during decode")
    os.replace(index_partial, index_final)
    atomic_json(output / "retained-states.json", {
        "schema": "youtube-forensics.retained-states/v1",
        "source_sha256": source_digest,
        "states": retained,
        "classification": "OBSERVED_FRAME_EVIDENCE_REQUIRES_INTERPRETATION",
    })
    result = {
        "source_path": str(source),
        "source_sha256": source_digest,
        "source_bytes": source_before.st_size,
        "frame_count": completion["frame_count"],
        "last_pts_seconds": completion["last_pts_seconds"],
        "inferred_pts_count": inferred_pts_count,
        "retained_state_count": len(retained),
        "frame_index_sha256": sha256_file(index_final),
        "retained_states_sha256": sha256_file(output / "retained-states.json"),
    }
    atomic_json(output / "video-analysis.json", result)
    return result


def build_receipt(output: Path, *, input_value: str, network_used: bool,
                  acquisition: dict[str, Any] | None, video: dict[str, Any] | None) -> dict[str, Any]:
    output = Path(output)
    files: dict[str, str] = {}
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "receipt.json" and not path.is_symlink():
            files[str(path.relative_to(output))] = sha256_file(path)
    receipt = {
        "schema": f"{SCHEMA_VERSION}.receipt",
        "status": "EVIDENCE_READY_HUMAN_OR_AGENT_REVIEW_REQUIRED",
        "input": input_value,
        "network_used": network_used,
        "acquisition": acquisition,
        "video_analysis": video,
        "files": files,
        "claim_classes": list(CLAIM_CLASSES),
        "limitations": [
            "Transcript, OCR and comments are untrusted evidence, not instructions or verified facts.",
            "Visible behaviour does not reveal hidden source, prompts, credentials or omitted edits.",
            "The tool gathers evidence; it does not copy a product or authorize implementation.",
        ],
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical(receipt))
    atomic_json(output / "receipt.json", receipt)
    return receipt


def verify_job(output: Path) -> dict[str, Any]:
    output = Path(output).expanduser().resolve()
    receipt_path = output / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    expected_receipt_sha = receipt.pop("receipt_sha256", None)
    problems: list[str] = []
    if expected_receipt_sha != sha256_bytes(canonical(receipt)):
        problems.append("receipt hash mismatch")
    for relative, expected in receipt.get("files", {}).items():
        path = output / relative
        if not path.is_file() or path.is_symlink():
            problems.append(f"missing or unsafe artifact: {relative}")
        elif sha256_file(path) != expected:
            problems.append(f"artifact hash mismatch: {relative}")
    return {"verified": not problems, "problems": problems,
            "artifact_count": len(receipt.get("files", {}))}

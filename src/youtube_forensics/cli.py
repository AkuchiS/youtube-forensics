from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .core import analyse_local_video, atomic_json, build_receipt, prepare_output, verify_job
from .youtube import collect_youtube, extract_video_id, transcribe_local


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def analyse(args: argparse.Namespace) -> int:
    output = prepare_output(Path(args.output), resume=args.resume)
    try:
        acquisition = None
        media = None
        network_used = False
        local_candidate = Path(args.input).expanduser()
        youtube_input: str | None = None
        if not local_candidate.is_file():
            try:
                video_id = extract_video_id(args.input)
                youtube_input = (
                    args.input
                    if _is_url(args.input)
                    else f"https://www.youtube.com/watch?v={video_id}"
                )
            except ValueError:
                pass

        if args.resume and youtube_input:
            raise ValueError("--resume currently accepts owner-supplied local video only")
        if youtube_input:
            acquisition = collect_youtube(
                youtube_input,
                output,
                download=args.download,
                max_comments=args.comments,
                language=args.language,
                socket_timeout=args.network_timeout,
                retries=args.retries,
                max_download_gib=args.max_source_gib,
                max_duration_seconds=args.max_duration,
            )
            network_used = True
            if acquisition.get("media_path"):
                media = Path(acquisition["media_path"])
        else:
            media = local_candidate.resolve()
            if not media.is_file():
                raise ValueError(f"Input is neither a URL nor a file: {args.input}")
            if media.stat().st_size > args.max_source_gib * 1024**3:
                raise ValueError(f"Local source exceeds {args.max_source_gib} GiB limit")

        free_gib = shutil.disk_usage(output).free / 1024**3
        if free_gib < args.min_free_gib:
            raise RuntimeError(
                f"Only {free_gib:.2f} GiB free; {args.min_free_gib:.2f} GiB is required"
            )

        video = None
        if media:
            video = analyse_local_video(
                media,
                output,
                threshold=args.threshold,
                minimum_gap_seconds=args.minimum_gap,
                resume=args.resume,
                checkpoint_interval=args.checkpoint_interval,
            )
            if args.local_asr:
                asr = transcribe_local(media, output, args.asr_model)
                video["local_asr"] = asr
        elif args.download:
            raise RuntimeError("Download was requested but no media file was produced")

        receipt = build_receipt(
            output,
            input_value=args.input,
            network_used=network_used,
            acquisition=acquisition,
            video=video,
        )
        print(
            json.dumps(
                {"output": str(output), "receipt": receipt}, ensure_ascii=False, sort_keys=True
            )
        )
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        atomic_json(
            output / "failure.json",
            {
                "schema": "youtube-forensics.failure/v1",
                "status": "FAILED",
                "input": args.input,
                "error_type": type(exc).__name__,
                "error": str(exc),
                "recorded_at": datetime.now(UTC).isoformat(),
                "resumable": (
                    (output / ".frame-index.partial.jsonl").is_file()
                    and (output / ".frame-checkpoint.json").is_file()
                ),
            },
        )
        raise


def verify(args: argparse.Namespace) -> int:
    result = verify_job(Path(args.output))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verified"] else 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="youtube-forensics")
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    run = commands.add_parser(
        "analyse", aliases=["analyze"], help="Collect and hash-bound video evidence"
    )
    run.add_argument("input", help="YouTube URL/video ID or local video path")
    run.add_argument("--output", required=True, help="New or empty evidence directory")
    run.add_argument(
        "--download", action="store_true", help="Download URL media for every-frame analysis"
    )
    run.add_argument(
        "--comments", type=int, default=200, help="Maximum public comments to retain (0-2000)"
    )
    run.add_argument("--language", default="en", help="Preferred caption language")
    run.add_argument(
        "--threshold", type=float, default=0.18, help="Perceptual-hash change threshold"
    )
    run.add_argument(
        "--minimum-gap", type=float, default=0.35, help="Minimum seconds between retained states"
    )
    run.add_argument(
        "--local-asr", action="store_true", help="Run optional local faster-whisper transcription"
    )
    run.add_argument(
        "--asr-model", default="small.en", help="faster-whisper model used with --local-asr"
    )
    run.add_argument(
        "--resume", action="store_true", help="Resume a checkpointed owner-supplied local-video job"
    )
    run.add_argument(
        "--checkpoint-interval",
        type=int,
        default=250,
        help="Frames between durable local-analysis checkpoints",
    )
    run.add_argument(
        "--network-timeout", type=float, default=20.0, help="Per-request network timeout in seconds"
    )
    run.add_argument("--retries", type=int, default=3, help="Bounded network/extractor retry count")
    run.add_argument(
        "--max-source-gib", type=float, default=20.0, help="Maximum local or downloaded source size"
    )
    run.add_argument(
        "--max-duration",
        type=float,
        default=21600.0,
        help="Maximum remote video duration in seconds",
    )
    run.add_argument(
        "--min-free-gib", type=float, default=2.0, help="Minimum free space required at job start"
    )
    run.set_defaults(func=analyse)
    check = commands.add_parser("verify", help="Recompute all receipt hashes")
    check.add_argument("output", help="Evidence directory containing receipt.json")
    check.set_defaults(func=verify)
    return root


def main() -> None:
    try:
        args = parser().parse_args()
        raise SystemExit(args.func(args))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"youtube-forensics: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import __version__
from .core import analyse_local_video, atomic_json, build_receipt, prepare_output, verify_job
from .youtube import canonical_youtube_url, collect_youtube, transcribe_local


def _require_free_space(path: Path, minimum_gib: float) -> None:
    free_gib = shutil.disk_usage(path).free / 1024**3
    if free_gib < minimum_gib:
        raise RuntimeError(f"Only {free_gib:.2f} GiB free; {minimum_gib:.2f} GiB is required")


def _failure_details(exc: BaseException, input_value: str, output: Path) -> tuple[str, str]:
    """Return useful failure text without disclosing owner filesystem paths."""
    source = Path(input_value).expanduser()
    safe_input = input_value
    with contextlib.suppress(ValueError):
        safe_input = canonical_youtube_url(input_value)
    if safe_input == input_value:
        safe_input = source.name or "local-input"

    error = str(exc)
    replacements = {
        str(output.resolve()): "<output>",
        str(output): "<output>",
        str(source.resolve()): source.name or "<local-input>",
        str(source): source.name or "<local-input>",
        input_value: safe_input,
    }
    for original, replacement in sorted(replacements.items(), key=lambda item: -len(item[0])):
        if original:
            error = error.replace(original, replacement)
    return safe_input, error


def analyse(args: argparse.Namespace) -> int:
    output = prepare_output(Path(args.output), resume=args.resume)
    try:
        acquisition = None
        media = None
        network_used = False
        local_candidate = Path(args.input).expanduser()
        youtube_input: str | None = None
        if not local_candidate.is_file():
            with contextlib.suppress(ValueError):
                youtube_input = canonical_youtube_url(args.input)

        if args.resume and youtube_input:
            raise ValueError("--resume currently accepts owner-supplied local video only")
        initial_free_gib = args.min_free_gib + (
            args.max_source_gib if youtube_input and args.download else 0
        )
        _require_free_space(output, initial_free_gib)
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
                relative_media = Path(acquisition["media_path"])
                if relative_media.is_absolute() or ".." in relative_media.parts:
                    raise ValueError("Acquisition returned an unsafe media path")
                media = output / relative_media
        else:
            if local_candidate.is_symlink():
                raise ValueError("Local source must not be a symlink")
            media = local_candidate.resolve()
            if not media.is_file():
                raise ValueError(f"Input is neither a URL nor a file: {args.input}")
            if media.stat().st_size > args.max_source_gib * 1024**3:
                raise ValueError(f"Local source exceeds {args.max_source_gib} GiB limit")

        # A fragmented remote download can consume the reserve after admission.
        _require_free_space(output, args.min_free_gib)

        video = None
        if media:
            video = analyse_local_video(
                media,
                output,
                threshold=args.threshold,
                minimum_gap_seconds=args.minimum_gap,
                resume=args.resume,
                checkpoint_interval=args.checkpoint_interval,
                min_free_bytes=int(args.min_free_gib * 1024**3),
            )
            if args.local_asr:
                asr = transcribe_local(
                    media,
                    output,
                    args.asr_model,
                    allow_model_download=args.allow_asr_model_download,
                )
                video["local_asr"] = asr
                network_used = network_used or args.allow_asr_model_download
                _require_free_space(output, args.min_free_gib)
        elif args.download:
            raise RuntimeError("Download was requested but no media file was produced")

        # A prior interrupted-run marker is not part of successful evidence.
        (output / "failure.json").unlink(missing_ok=True)
        receipt = build_receipt(
            output,
            input_value=youtube_input or media.name,
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
        safe_input, safe_error = _failure_details(exc, args.input, output)
        atomic_json(
            output / "failure.json",
            {
                "schema": "youtube-forensics.failure/v1",
                "status": "FAILED",
                "input": safe_input,
                "error_type": type(exc).__name__,
                "error": safe_error,
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
        "--allow-asr-model-download",
        action="store_true",
        help="Allow faster-whisper to fetch a missing model; otherwise ASR is cache/local-only",
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

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

from .core import analyse_local_video, build_receipt, ensure_new_output, verify_job
from .youtube import collect_youtube, extract_video_id, transcribe_local


def _is_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def analyse(args: argparse.Namespace) -> int:
    output = ensure_new_output(Path(args.output))
    acquisition = None
    media = None
    network_used = False
    local_candidate = Path(args.input).expanduser()
    youtube_input: str | None = None
    if not local_candidate.is_file():
        try:
            video_id = extract_video_id(args.input)
            youtube_input = (args.input if _is_url(args.input)
                             else f"https://www.youtube.com/watch?v={video_id}")
        except ValueError:
            pass

    if youtube_input:
        acquisition = collect_youtube(youtube_input, output, download=args.download,
                                      max_comments=args.comments, language=args.language)
        network_used = True
        if acquisition.get("media_path"):
            media = Path(acquisition["media_path"])
    else:
        media = local_candidate.resolve()
        if not media.is_file():
            raise ValueError(f"Input is neither a URL nor a file: {args.input}")

    video = None
    if media:
        video = analyse_local_video(media, output, threshold=args.threshold,
                                    minimum_gap_seconds=args.minimum_gap)
        if args.local_asr:
            asr = transcribe_local(media, output, args.asr_model)
            video["local_asr"] = asr
    elif args.download:
        raise RuntimeError("Download was requested but no media file was produced")

    receipt = build_receipt(output, input_value=args.input, network_used=network_used,
                            acquisition=acquisition, video=video)
    print(json.dumps({"output": str(output), "receipt": receipt}, ensure_ascii=False,
                     sort_keys=True))
    return 0


def verify(args: argparse.Namespace) -> int:
    result = verify_job(Path(args.output))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verified"] else 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="youtube-forensics")
    commands = root.add_subparsers(dest="command", required=True)
    run = commands.add_parser("analyse", aliases=["analyze"],
                              help="Collect and hash-bound video evidence")
    run.add_argument("input", help="YouTube URL/video ID or local video path")
    run.add_argument("--output", required=True, help="New or empty evidence directory")
    run.add_argument("--download", action="store_true",
                     help="Download URL media for every-frame analysis")
    run.add_argument("--comments", type=int, default=200,
                     help="Maximum public comments to retain (0-2000)")
    run.add_argument("--language", default="en", help="Preferred caption language")
    run.add_argument("--threshold", type=float, default=0.18,
                     help="Perceptual-hash change threshold")
    run.add_argument("--minimum-gap", type=float, default=0.35,
                     help="Minimum seconds between retained states")
    run.add_argument("--local-asr", action="store_true",
                     help="Run optional local faster-whisper transcription")
    run.add_argument("--asr-model", default="small.en",
                     help="faster-whisper model used with --local-asr")
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
        raise SystemExit(1)


if __name__ == "__main__":
    main()

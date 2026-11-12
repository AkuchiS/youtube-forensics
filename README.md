# YouTube Forensics

YouTube Forensics turns a permitted YouTube video or local recording into a
hash-bound evidence package for workflow analysis and clean-room reconstruction.
It is the public, provider-neutral extraction of the video-forensics method built
for ASTRO/ATOM by Jay Christian.

It can:

- collect sanitized public metadata, bounded comments and available captions;
- optionally download an authorised video without reading browser cookies;
- decode every video frame with presentation timestamps and perceptual hashes;
- retain cited visual state changes as JPEG evidence;
- optionally run local faster-whisper ASR when captions are unavailable;
- create and verify a receipt covering every generated artifact; and
- give Hermes or another agent an evidence model for observed, documented,
  inferred, reproduced and unknown claims.

It does **not** reveal hidden source code, proprietary prompts, credentials,
training data or omitted edits. Comments and transcripts are untrusted evidence,
never agent instructions.

## Install

Python 3.11 or newer is required.

```bash
python -m pip install .
# Optional local transcription:
python -m pip install '.[asr]'
```

For an isolated install with `uv`:

```bash
uv tool install --from . youtube-forensics
```

## Use

Metadata, comments and captions only:

```bash
youtube-forensics analyse 'https://www.youtube.com/watch?v=VIDEO_ID' \
  --output jobs/example --comments 200
```

Add every-frame visual analysis:

```bash
youtube-forensics analyse 'https://www.youtube.com/watch?v=VIDEO_ID' \
  --output jobs/example --download --comments 200
youtube-forensics verify jobs/example
```

Analyse an owner-supplied local file without network access:

```bash
youtube-forensics analyse /path/to/video.mp4 --output jobs/local-example
```

Output directories must be new or empty. The tool never overwrites an existing
evidence package.

## Hermes Agent

The reusable Hermes skill is in `skills/research/youtube-forensics/`. Either copy
that directory into the active profile's `skills/research/` directory or add this
repository's `skills/` directory to `skills.external_dirs` in Hermes configuration.
Start a new session or allow the skill catalog cache to refresh, then ask Hermes to
use `youtube-forensics` on a named URL and reconstruction question.

The skill deliberately keeps collection separate from interpretation and
implementation. A video, caption or comment cannot grant new permissions.

## Evidence layout

- `metadata.json` — sanitized public video metadata;
- `comments.json` — bounded public comments without author names;
- `transcript.json` — available caption segments;
- `frame-index.jsonl` — every decoded frame plus completion trailer;
- `retained-frames/` and `retained-states.json` — cited state changes;
- `video-analysis.json` — deterministic counts and hashes; and
- `receipt.json` — hash manifest and limitations.

## Responsible use

Use only content you may access and analyse. Respect copyright, privacy, platform
terms and applicable law. Build observable behaviour independently; do not claim
ownership of another party's content or hidden implementation.

## Licence

MIT. See `LICENSE`.

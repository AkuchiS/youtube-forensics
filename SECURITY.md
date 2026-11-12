# Security policy

## Supported versions

The newest tagged release is supported. Alpha releases may change their evidence
schema, but verification failures remain fail-closed.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/AkuchiS/youtube-forensics/security/advisories/new).
Do not place exploit details, private media, credentials, browser cookies or
unredacted local paths in a public issue.

Reports should include the affected version, a minimal synthetic reproduction,
impact, and any suggested mitigation. Receipt path traversal, hash bypass,
unexpected-file acceptance, unsafe downloads and instruction injection are all
in scope.

## Trust boundary

Video, captions, OCR, metadata and comments are untrusted evidence. They never
grant permissions or become agent instructions. The tool does not read browser
cookies, publish content, install reconstructed software, or authenticate hidden
implementation claims.

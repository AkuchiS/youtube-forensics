# Contributing

Contributions are welcome when they preserve the evidence boundary and include a
deterministic acceptance test.

1. Open an issue describing the observable outcome and rights/privacy boundary.
2. Work on a branch; do not include private media, credentials or browser state.
3. Run `python -m pytest -q`, `python -m ruff check .`, and build the wheel/sdist.
4. Explain whether each new claim is observed, documented, inferred, reproduced,
   or unknown.
5. Submit a focused pull request. Maintainers may request a synthetic fixture.

Do not add mechanisms for cookie theft, access-control bypass, mass scraping,
automated platform engagement, or copying hidden proprietary implementation.

# Publication checklist

Use this checklist before creating a GitHub repository or changing its visibility.

1. Review the threat model and security limitations in `SECURITY.md` and `docs/THREAT_MODEL.md`.
2. Start from a fresh clone on a supported Python version.
3. Run `python -m pip install -r requirements.txt` and `python -m pytest -q`.
4. On Windows, run `scripts\install_windows.cmd` from an x64 MSVC developer prompt.
5. Confirm that native build outputs, virtual environments, databases, keys, reports, and local paths are absent from `git ls-files`.
6. Run the repository hygiene workflow and dependency audit in CI.
7. Review the final diff with a human maintainer, choose the repository owner and license details, then publish the reviewed commit.

The repository contains source code and reproducibility instructions only. Native binaries and validation reports are generated locally and are ignored by Git.

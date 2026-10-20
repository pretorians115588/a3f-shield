# Upload precheck

The repository is prepared for a human-reviewed GitHub upload when all of the
following are complete:

- replace the local placeholder remote with the chosen GitHub repository URL;
- verify `CITATION.cff`, `AUTHORS.md`, `LICENSE`, and `NOTICE.md`;
- review the staged diff and create the first signed release commit;
- run the Linux and Windows CI workflows from a fresh clone;
- publish the repository privately first, then change visibility only after
  the final human review.

No remote, token, or repository URL is embedded in this working copy.

# Contributing

Contributions are welcome when they preserve the fail-closed and claim-boundary
contracts.

1. Fork the repository and create a focused branch.
2. Do not add restricted data, credentials, local paths, raw sequence or patient
   records, or scientific rows without complete rights and provenance records.
3. Add positive and adversarial tests for every state transition or trust-boundary
   change.
4. Run `uv sync --frozen --extra dev`, tests under normal and optimized Python, Ruff,
   pre-commit, the privacy scanner, and the package checks.
5. Submit a pull request describing the risk addressed and exact acceptance evidence.

No contribution may turn byte integrity into a truth claim, raise empirical `N`, or
imply clinical, experimental, target-selection, or release authority merely because
software checks pass.

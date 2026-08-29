#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

EXCLUDED_DIRECTORIES = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "htmlcov",
    "temp_docs_and_tests",
}
FORBIDDEN_NAMES = {
    ".env",
    ".env.local",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
    "secrets.json",
}
GENERATED_FILE_NAMES = {".coverage", "coverage.xml"}
FORBIDDEN_SUFFIXES = {
    ".bam",
    ".bcf",
    ".cram",
    ".fa",
    ".fasta",
    ".fastq",
    ".fq",
    ".sam",
    ".vcf",
    ".vcf.gz",
    ".fastq.gz",
    ".fq.gz",
}
MAX_PUBLIC_FILE_BYTES = 2 * 1024 * 1024

SECRET_PATTERNS = {
    "SECRET_GITHUB_TOKEN": re.compile("gh" + r"[opsu]_[A-Za-z0-9]{20,}"),
    "SECRET_OPENAI_TOKEN": re.compile("s" + r"k-[A-Za-z0-9_-]{20,}"),
    "SECRET_AWS_ACCESS_KEY": re.compile("AK" + r"IA[0-9A-Z]{16}"),
    "SECRET_PRIVATE_KEY": re.compile("BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY"),
}
LOCAL_PATH_PATTERN = re.compile(r"(?<![A-Za-z0-9.:])/(?:Users|home)/[^/\s]+/")


def _walk_files(root: Path) -> list[Path]:
    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not any(part in EXCLUDED_DIRECTORIES for part in path.parts)
    ]


def scan(root: Path) -> list[str]:
    root = root.resolve()
    files = _walk_files(root)
    issues: list[str] = []
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        if path.name in GENERATED_FILE_NAMES:
            continue
        if path.is_symlink():
            issues.append("FORBIDDEN_SYMLINK")
            continue
        if not path.exists():
            continue
        if path.name in FORBIDDEN_NAMES:
            issues.append("CREDENTIAL_FILENAME")
        lower = relative.lower()
        if any(lower.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            issues.append("RAW_BIOLOGICAL_PAYLOAD")
        size = path.stat().st_size
        if size > MAX_PUBLIC_FILE_BYTES:
            issues.append("OVERSIZED_PUBLIC_FILE")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            issues.append("UNEXPECTED_BINARY_FILE")
            continue
        for issue_code, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                issues.append(issue_code)
        if LOCAL_PATH_PATTERN.search(text):
            issues.append("PRIVATE_ABSOLUTE_PATH")
    return issues


def main(argv: list[str] | None = None) -> int:
    arguments = argv if argv is not None else sys.argv[1:]
    try:
        root = Path(arguments[0]) if arguments else Path.cwd()
        issues = scan(root)
        file_count = len(_walk_files(root.resolve()))
    except (OSError, RuntimeError, UnicodeError, ValueError):
        print("FAIL privacy scan: unable to complete safe scan")
        return 2
    if issues:
        print("FAIL privacy scan: forbidden public-release material detected")
        return 2
    print(f"PASS privacy scan: {file_count} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

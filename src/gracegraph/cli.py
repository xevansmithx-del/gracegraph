"""Command-line interface for GraceGraph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .canonical import GraceGraphError
from .capsule import compile_capsule, diff_capsules, explain_node, verify_capsule
from .models import COMPILER_VERSION


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gracegraph")
    parser.add_argument("--version", action="version", version=f"%(prog)s {COMPILER_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)
    compile_cmd = sub.add_parser("compile", help="compile a deterministic evidence capsule")
    compile_cmd.add_argument("spec", type=Path)
    compile_cmd.add_argument("--project-root", type=Path, required=True)
    compile_cmd.add_argument("--out", type=Path, required=True)
    verify_cmd = sub.add_parser("verify", help="verify exact capsule membership and hashes")
    verify_cmd.add_argument("capsule", type=Path)
    verify_cmd.add_argument("--project-root", type=Path)
    diff_cmd = sub.add_parser("diff", help="show node-state changes between capsules")
    diff_cmd.add_argument("old", type=Path)
    diff_cmd.add_argument("new", type=Path)
    explain_cmd = sub.add_parser("explain", help="explain one node and its direct evidence edges")
    explain_cmd.add_argument("capsule", type=Path)
    explain_cmd.add_argument("node_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "compile":
            result = compile_capsule(args.spec, args.project_root, args.out)
        elif args.command == "verify":
            result = verify_capsule(args.capsule, args.project_root)
        elif args.command == "diff":
            result = diff_capsules(args.old, args.new)
        else:
            result = explain_node(args.capsule, args.node_id)
        print(json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False))
        return 0
    except (GraceGraphError, OSError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

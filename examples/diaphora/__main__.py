"""Command line entry point for the native Diaphora database workflow."""

from __future__ import annotations

import argparse
import json

from .backend import diff_databases


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True,
                        help="Diaphora 3.4.0 checkout at the recorded revision")
    commands = parser.add_subparsers(dest="command", required=True)
    diff = commands.add_parser("diff", help="Match two native Diaphora SQLite exports")
    diff.add_argument("primary")
    diff.add_argument("secondary")
    diff.add_argument("output", help="New native Diaphora SQLite results file")
    diff.add_argument("--all-heuristics", action="store_true")
    diff.add_argument("--relaxed-ratio", action="store_true")
    diff.add_argument("--trained-model", action="store_true")
    args = parser.parse_args(argv)
    result = diff_databases(args.upstream, args.primary, args.secondary, args.output,
                            all_heuristics=args.all_heuristics,
                            relaxed_ratio=args.relaxed_ratio,
                            use_model=args.trained_model)
    print(json.dumps({category: len(rows) for category, rows in result.items()}, sort_keys=True))


if __name__ == "__main__":
    main()

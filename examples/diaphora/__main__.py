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
    export = commands.add_parser("export", help="Export a binary or IDB through the opaque IDAX host")
    export.add_argument("input")
    export.add_argument("output", help="Native Diaphora SQLite export")
    export.add_argument("--no-decompiler", action="store_true")
    export.add_argument("--no-microcode", action="store_true")
    export.add_argument("--include-library-thunks", action="store_true")
    export.add_argument("--exclude-auto-names", action="store_true")
    export.add_argument("--project-script")
    export.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "export":
        from idax import database
        from .host import export_current_database
        database.init()
        with database.opened(args.input, save_on_exit=False):
            result = export_current_database(args.upstream, args.output,
                use_decompiler=not args.no_decompiler, microcode=not args.no_microcode,
                include_library_thunks=args.include_library_thunks,
                include_auto_names=not args.exclude_auto_names,
                project_script=args.project_script, resume=args.resume)
        print(json.dumps(result, sort_keys=True))
        return
    result = diff_databases(args.upstream, args.primary, args.secondary, args.output,
                            all_heuristics=args.all_heuristics,
                            relaxed_ratio=args.relaxed_ratio,
                            use_model=args.trained_model)
    print(json.dumps({category: len(rows) for category, rows in result.items()}, sort_keys=True))


if __name__ == "__main__":
    main()

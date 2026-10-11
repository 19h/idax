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
    metadata = commands.add_parser("import", help="Apply selected native results and save a new IDB")
    metadata.add_argument("input", help="Primary binary or IDB")
    metadata.add_argument("results", help="Native Diaphora results database")
    metadata.add_argument("output", help="New IDB destination")
    metadata.add_argument("--category", action="append", choices=("best", "partial", "unreliable", "multimatch"))
    metadata.add_argument("--no-definitions", action="store_true")
    metadata.add_argument("--force-names", action="store_true")
    render = commands.add_parser("render", help="Generate audited HTML differences without an IDA runtime")
    render.add_argument("primary")
    render.add_argument("secondary")
    render.add_argument("first", type=lambda text: int(text, 0))
    render.add_argument("second", type=lambda text: int(text, 0))
    render.add_argument("output", help="New UTF-8 HTML file")
    render.add_argument("--field", choices=("assembly", "pseudocode", "microcode"), default="assembly")
    render.add_argument("--style", choices=("side-by-side", "patch"), default="side-by-side")
    preview = commands.add_parser("preview", help="Generate an audited single-function HTML preview")
    preview.add_argument("primary")
    preview.add_argument("secondary")
    preview.add_argument("address", type=lambda text: int(text, 0))
    preview.add_argument("output", help="New UTF-8 HTML file")
    preview.add_argument("--secondary-side", action="store_true")
    preview.add_argument("--field", choices=("assembly", "pseudocode"), default="assembly")
    graph = commands.add_parser("graph", help="Copy native colored graph presentation into JSON")
    graph.add_argument("primary")
    graph.add_argument("secondary")
    graph.add_argument("first", type=lambda text: int(text, 0))
    graph.add_argument("second", type=lambda text: int(text, 0))
    graph.add_argument("output", help="New graph-model JSON file")
    graph.add_argument("--kind", choices=("native", "microcode", "calls"), default="native")
    args = parser.parse_args(argv)
    if args.command in ("render", "preview"):
        from .presentation import render_diff, render_source, save_html
        if args.command == "render":
            result = render_diff(args.upstream, args.primary, args.secondary, args.first,
                args.second, field=args.field, html=args.style == "side-by-side")
        else:
            result = render_source(args.upstream, args.primary, args.secondary, args.address,
                primary_side=not args.secondary_side, field=args.field)
        save_html(result, args.output)
        print(json.dumps({"title": result.title, "characters": len(result.content)}, sort_keys=True))
        return
    if args.command == "graph":
        from dataclasses import asdict
        from pathlib import Path
        from .presentation import callgraph_pair, graph_pair
        result = callgraph_pair(args.upstream, args.primary, args.secondary, args.first, args.second) \
            if args.kind == "calls" else graph_pair(args.upstream, args.primary, args.secondary,
                args.first, args.second, microcode=args.kind == "microcode")
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as stream:
            json.dump([asdict(model) for model in result], stream, indent=2)
            stream.write("\n")
        print(json.dumps({"graphs": len(result), "nodes": [len(model.nodes) for model in result],
            "edges": [len(model.edges) for model in result]}, sort_keys=True))
        return
    if args.command == "import":
        from pathlib import Path
        from idax import database
        from .metadata import import_results
        output = Path(args.output).resolve()
        if output.exists():
            raise FileExistsError(output)
        database.init()
        with database.opened(args.input, save_on_exit=False):
            count = import_results(args.upstream, args.results,
                categories=tuple(args.category or ("best",)),
                definitions=not args.no_definitions, force=args.force_names)
            database.save_to(output)
        print(json.dumps({"imported": count}, sort_keys=True))
        return
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

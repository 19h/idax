#!/usr/bin/env python3
"""Build a native IDA addon from Swift sources and a named @_cdecl bootstrap.

Native SDK/runtime dependencies are linked normally. Each build uses the host
architecture; it does not claim cross-architecture or xcframework support.
"""

import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile


def run(arguments: list[str], *, environment: dict[str, str], capture: bool = False) -> str:
    result = subprocess.run(arguments, env=environment, text=True, check=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=("plugin", "loader", "processor"))
    parser.add_argument("--name", required=True, help="Swift module name")
    parser.add_argument("--symbol", required=True, help="C bootstrap symbol exported by @_cdecl")
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--support-dir", type=Path, required=True,
                        help="One common IDAXShared directory for all addons loaded by the same host")
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--configuration", choices=("debug", "release"), default="release")
    options = parser.parse_args()
    for value in (options.name, options.symbol):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is None:
            parser.error("Module name and bootstrap symbol must be identifiers")
    if sys.platform not in ("darwin", "linux"):
        parser.error("Swift addon builds currently support macOS and Linux")
    runtime_value = os.environ.get("IDADIR")
    if not runtime_value:
        parser.error("Set IDADIR to the IDA 9.4 runtime directory")
    sdk_value = os.environ.get("IDASDK")
    if not sdk_value:
        parser.error("Set IDASDK to the IDA 9.4 SDK source directory")
    runtime = Path(runtime_value).resolve()
    output = options.output.resolve()
    support = options.support_dir.resolve()
    repository = Path(__file__).resolve().parents[3]
    build = (options.build_dir or repository / ("build-swift-module-" + options.name)).resolve()
    environment = dict(os.environ)
    configure = ["cmake", "-S", str(repository), "-B", str(build),
                 "-DCMAKE_BUILD_TYPE=Release", "-DIDAX_BUILD_SWIFT=ON",
                 "-DIDASDK=" + str(Path(sdk_value).resolve()),
                 "-DIDAX_BUILD_TESTS=OFF", "-DIDAX_BUILD_EXAMPLES=OFF",
                 "-DIDAX_SWIFT_RUNTIME_DIR=" + str(runtime),
                 "-DIDAX_SWIFT_MODULE_KIND=" + options.kind,
                 "-DIDAX_SWIFT_MODULE_SYMBOL=" + options.symbol]
    if sys.platform == "darwin":
        configure.append("-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0")
    run(configure, environment=environment)
    run(["cmake", "--build", str(build), "--config", "Release", "--target", "idax_swift_native", "idax_swift_module_entry", "--parallel"], environment=environment)
    native = build / "bindings" / "swift"
    previous = environment.get("PKG_CONFIG_PATH", "")
    environment["PKG_CONFIG_PATH"] = str(native / "pkgconfig") + (os.pathsep + previous if previous else "")
    # Swift types and native runtime state must exist once per host process.
    # Every addon links this same shared image instead of embedding IDAX types.
    swift_build = ["swift", "build", "--build-system", "native", "--package-path", str(repository),
                   "--configuration", options.configuration]
    products = Path(run(swift_build + ["--show-bin-path"], environment=environment, capture=True))
    library_name = "libIDAXShared." + ("dylib" if sys.platform == "darwin" else "so")
    library = products / library_name
    # pkg-config libraries are absent from SwiftPM's incremental link inputs.
    # Relink the owned output so a C++-only change cannot reuse a stale image.
    library.unlink(missing_ok=True)
    run(swift_build + ["-Xlinker", "-rpath", "-Xlinker", str(runtime), "--product", "IDAXShared"],
        environment=environment)
    if not library.is_file():
        raise RuntimeError("SwiftPM produced no IDAXShared dynamic library")
    support.mkdir(parents=True, exist_ok=True)
    # Replace atomically so an existing mapped support image is not rewritten.
    with tempfile.NamedTemporaryFile(prefix=".idax-shared-", dir=support, delete=False) as temporary:
        copied_library = Path(temporary.name)
    try:
        shutil.copy2(library, copied_library)
        copied_library.replace(support / library_name)
    finally:
        copied_library.unlink(missing_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    relative_support = os.path.relpath(support, output.parent)
    command = ["swiftc", "-swift-version", "6", "-emit-library", "-module-name", options.name,
               "-I", str(products / "Modules"), "-I", str(repository / "bindings/swift/Sources/CIDAX"),
               *[str(source.resolve()) for source in options.source]]
    entry = str(native / "libidax_swift_module_entry.a")
    if sys.platform == "darwin":
        command += ["-target", platform.machine() + "-apple-macosx13.0",
                    "-Xlinker", "-force_load", "-Xlinker", entry,
                    "-Xlinker", "-install_name", "-Xlinker", "@rpath/" + output.name,
                    "-Xlinker", "-rpath", "-Xlinker", "@loader_path/" + relative_support]
    else:
        command += ["-Xlinker", "--whole-archive", "-Xlinker", entry,
                    "-Xlinker", "--no-whole-archive", "-Xlinker", "--no-undefined",
                    "-Xlinker", "-soname", "-Xlinker", output.name,
                    "-Xlinker", "-Bsymbolic", "-Xlinker", "-rpath", "-Xlinker", "$ORIGIN/" + relative_support]
    # Put archives referenced by the entry after that entry for one-pass Unix
    # linkers; platform libraries follow the complete native transport.
    command += ["-L", str(support), "-lIDAXShared", "-L", str(native),
                "-L", str(runtime), "-lidalib", "-lida", "-lc++" if sys.platform == "darwin" else "-lstdc++",
                "-Xlinker", "-rpath", "-Xlinker", str(runtime), "-o", str(output)]
    run(command, environment=environment)
    native_export = {"plugin": "PLUGIN", "loader": "LDSC", "processor": "LPH"}[options.kind]
    if sys.platform == "darwin":
        symbols = set(run(["nm", "-gjU", str(output)], environment=environment, capture=True).splitlines())
        definitions = set(run(["nm", "-jU", str(output)], environment=environment, capture=True).splitlines())
        required = {"_" + native_export, "_" + options.symbol}
    else:
        listing = run(["nm", "--defined-only", "--extern-only", str(output)],
                      environment=environment, capture=True)
        symbols = {line.split()[-1] for line in listing.splitlines() if line.split()}
        definitions = symbols
        required = {native_export, options.symbol}
    if not required.issubset(symbols):
        raise RuntimeError("Addon image does not define its SDK entry and Swift bootstrap exports")
    descriptor_symbols = {"_" + name if sys.platform == "darwin" else name for name in ("PLUGIN", "LDSC", "LPH")}
    expected_descriptor = "_" + native_export if sys.platform == "darwin" else native_export
    if symbols.intersection(descriptor_symbols) != {expected_descriptor}:
        raise RuntimeError("Addon defines an unrelated SDK descriptor")
    if any("OBJC_CLASS_$__TtC4IDAX" in symbol for symbol in definitions):
        raise RuntimeError("Addon duplicates the shared IDAX Swift classes")
    print("PASS: addon defines only its SDK entry and uses shared IDAX Swift types")
    print(output)


if __name__ == "__main__":
    main()

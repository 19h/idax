#!/usr/bin/env python3
"""Verify relocated Swift addons through actual IDA kernel dispatch.

Build the three example addons plus Tests/ModuleHost/SecondPlugin.swift with
build-module.py into a common {plugins,loaders,procs,lib} tree. This verifier
relocates the entire tree, opens disposable inputs, checks loader selection,
processor decoding/rendering, and two independent plugin factories in one host.
"""

import argparse
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-root", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True,
                        help="Source-built native fixture to analyze, never execute")
    options = parser.parse_args()
    if sys.platform not in ("darwin", "linux"):
        parser.error("Module host verification currently supports macOS and Linux")
    sdk = os.environ.get("IDASDK")
    runtime = os.environ.get("IDADIR")
    if not sdk or not runtime:
        parser.error("Set IDASDK and IDADIR to the licensed IDA 9.4 SDK/runtime")
    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    names = {
        "first": "plugins/SwiftPluginExample" + suffix,
        "second": "plugins/SwiftSecondPlugin" + suffix,
        "loader": "loaders/SwiftLoaderExample" + suffix,
        "processor": "procs/SwiftProcessorExample" + suffix,
        "support": "lib/libIDAXShared" + suffix,
    }
    for relative in names.values():
        if not (options.module_root / relative).is_file():
            parser.error("Missing addon artifact: " + relative)
    if not options.fixture.is_file():
        parser.error("The native fixture does not exist")
    repository = Path(__file__).resolve().parents[3]
    with tempfile.TemporaryDirectory(prefix="idax-swift-module-host-") as temporary:
        work = Path(temporary)
        modules = work / "user"
        shutil.copytree(options.module_root, modules)
        fixture = work / "plugin-input"
        shutil.copy2(options.fixture, fixture)
        (work / "loader-input").write_bytes(b"IDAX\x00\x01\x02\x03")
        (work / "processor-input").write_bytes(b"\x00\x00\x01\x00")
        compiler = shlex.split(os.environ["CXX"]) if "CXX" in os.environ else (
            ["xcrun", "clang++"] if sys.platform == "darwin" else ["c++"])
        command = compiler + ["-std=c++17", "-D__EA64__", "-I" + str(Path(sdk) / "include")]
        command += ["-D__MAC__"] if sys.platform == "darwin" else ["-D__LINUX__"]
        if platform.machine().lower() in ("arm64", "aarch64"):
            command += ["-D__ARM__"]
        command += [str(repository / "bindings/swift/Tests/ModuleHost/main.cpp"),
                    "-L" + runtime, "-lidalib", "-lida", "-Wl,-rpath," + runtime,
                    "-o", str(work / "host")]
        compiled = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if compiled.returncode:
            raise RuntimeError("Host probe compilation failed:\n" + compiled.stderr)
        environment = dict(os.environ)
        existing = environment.get("IDAUSR", str(Path.home() / ".idapro"))
        environment["IDAUSR"] = str(modules) + (os.pathsep + existing if existing else "")
        cases = [
            ("plugin", fixture, str(modules / names["first"]), str(modules / names["second"])),
            ("loader", work / "loader-input", "SwiftLoaderExample"),
            ("processor", work / "processor-input", "SwiftProcessorExample"),
        ]
        for case in cases:
            result = subprocess.run([str(work / "host"), *map(str, case)],
                                    env=environment, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, timeout=120)
            if result.returncode or "IDAX_SWIFT_HOST_DISPATCH=PASS" not in result.stdout:
                raise RuntimeError(case[0] + " actual dispatch failed:\n" + result.stdout)
            if any("IDAX" in line and "is implemented in both" in line
                   for line in result.stdout.splitlines()):
                raise RuntimeError("Duplicate IDAX Swift classes in the addon host")
            if case[0] == "plugin":
                for marker in ("Swift IDAX argument: 4242", "Swift IDAX second argument: 5252",
                               "Swift IDAX argument: 6262"):
                    if result.stdout.count(marker) != 1:
                        raise RuntimeError("Plugin factories did not dispatch independently: " + marker)
            print("PASS: relocated " + case[0] + " actual SDK dispatch")


if __name__ == "__main__":
    main()

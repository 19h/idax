"""Print pseudocode for a function when a compatible Hex-Rays plugin exists."""

from __future__ import annotations

import argparse

from idax import decompiler


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("address", type=lambda value: int(value, 0))
    args = parser.parse_args()

    if not decompiler.available():
        raise SystemExit("compatible Hex-Rays decompiler unavailable")
    with decompiler.decompile(args.address) as result:
        print(result.declaration())
        print(result.pseudocode())


if __name__ == "__main__":
    main()

"""Print a compact function/instruction inventory from an external process."""

from __future__ import annotations

import argparse

from idax import database, function, instruction, xref


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    args = parser.parse_args()

    database.init(
        ["idax-python-inventory"],
        database.RuntimeOptions(
            quiet=True,
            plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True),
        ),
    )
    with database.opened(args.input, save_on_exit=False):
        print(database.processor_profile())
        for current in function.all():
            items = function.item_addresses(current.start)
            print(f"{current.start:#x} {current.name} ({len(items)} items)")
            for address in items[:3]:
                decoded = instruction.decode(address)
                print(
                    f"  {address:#x} {decoded.mnemonic} "
                    f"xrefs={len(xref.refs_from(address))}"
                )


if __name__ == "__main__":
    main()

"""Fresh-process initialized-host evidence for register-value tracking."""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

from idax import BAD_ADDRESS, ValidationError, analysis, database, name, registers


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("expected one AArch64 fixture path")
    with tempfile.TemporaryDirectory(prefix="idax-python-registers-") as directory:
        fixture = Path(directory) / "register_tracking_aarch64"
        shutil.copy2(Path(sys.argv[1]), fixture)
        options = database.RuntimeOptions(
            quiet=True,
            plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True),
        )
        database.init(["idax-python-registers"], options)
        database.open(fixture, database.OpenMode.ANALYZE)
        try:
            analysis.wait()
            start = name.resolve("_start", BAD_ADDRESS)
            assert registers.constant_at(start + 4, "x29") == 0
            constant = registers.track(start + 4, "x29")
            assert constant.state is registers.TrackingState.CONSTANT
            assert constant.known
            assert constant.candidates[0].constant == 0
            assert constant.candidates[0].origin.address == start

            assert registers.constant_at(start + 12, "x0") == 0x0000_ABCD_0000_1234
            assert registers.constant_at(start + 12, "w0") == 0x1234
            assert registers.constant_at(start + 12, "w0", -1) == 0x1234

            assert registers.stack_delta_at(start + 16) == -32
            stack = registers.track(start + 16, "sp")
            assert stack.state is registers.TrackingState.STACK_POINTER_DELTA
            assert stack.candidates

            input_value = registers.track(start, "x0")
            assert input_value.state in (
                registers.TrackingState.FUNCTION_INPUT,
                registers.TrackingState.UNDEFINED,
            )
            assert registers.constant_at(start, "x0") is None

            multi_join = name.resolve("multi_join", BAD_ADDRESS)
            multi = registers.track(multi_join, "x2")
            assert multi.state is registers.TrackingState.CONSTANT
            assert len(multi.candidates) == 2
            assert sorted(candidate.constant for candidate in multi.candidates) == [
                0x11,
                0x22,
            ]
            assert registers.constant_at(multi_join, "x2") is None

            nearest = registers.nearest_at(start + 12, "x29", "x0")
            assert nearest is not None
            assert nearest.selected_index == 0
            assert nearest.register_name == "x29"
            assert nearest.value.known

            try:
                registers.nearest_at(start + 12, "x0", "w0")
            except ValidationError:
                pass
            else:
                raise AssertionError("alias-equivalent nearest registers accepted")

            registers.control_flow_reference_changed(
                start,
                start + 4,
                registers.ReferenceMutation.ADDED,
            )
            registers.control_flow_reference_changed(
                start,
                start + 4,
                registers.ReferenceMutation.REMOVED,
            )
            registers.data_reference_changed(
                start, registers.ReferenceMutation.ADDED
            )
            registers.data_reference_changed(
                start, registers.ReferenceMutation.REMOVED
            )
            registers.clear_control_flow_cache()
            registers.clear_data_reference_cache()
        finally:
            database.close(False)


if __name__ == "__main__":
    main()

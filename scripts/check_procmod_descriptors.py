#!/usr/bin/env python3
"""Load each example procmod and verify its exported IDA 9.4 descriptor."""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from check_procmod_exports import ValidationError, _redact, find_module


PR_USE32 = 0x000002
PR_DEFSEG32 = 0x000004
PR_USE64 = 0x002000
PR_DEFSEG64 = 0x10000000


class InstructionDescriptor(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("feature", ctypes.c_uint32),
    ]


class ProcessorDescriptor(ctypes.Structure):
    """Complete pinned 64-bit IDA 9.4 ``processor_t`` layout."""

    _fields_ = [
        ("version", ctypes.c_int32),
        ("id", ctypes.c_int32),
        ("flag", ctypes.c_uint32),
        ("flag2", ctypes.c_uint32),
        ("cnbits", ctypes.c_int32),
        ("dnbits", ctypes.c_int32),
        ("psnames", ctypes.POINTER(ctypes.c_char_p)),
        ("plnames", ctypes.POINTER(ctypes.c_char_p)),
        ("assemblers", ctypes.POINTER(ctypes.c_void_p)),
        ("notify", ctypes.c_void_p),
        ("reg_names", ctypes.POINTER(ctypes.c_char_p)),
        ("regs_num", ctypes.c_int32),
        ("reg_first_sreg", ctypes.c_int32),
        ("reg_last_sreg", ctypes.c_int32),
        ("segreg_size", ctypes.c_int32),
        ("reg_code_sreg", ctypes.c_int32),
        ("reg_data_sreg", ctypes.c_int32),
        ("codestart", ctypes.c_void_p),
        ("retcodes", ctypes.c_void_p),
        ("instruc_start", ctypes.c_int32),
        ("instruc_end", ctypes.c_int32),
        ("instruc", ctypes.POINTER(InstructionDescriptor)),
        ("tbyte_size", ctypes.c_size_t),
        ("real_width", ctypes.c_char * 4),
        ("icode_return", ctypes.c_int32),
        ("unused_slot", ctypes.c_void_p),
    ]


@dataclass(frozen=True)
class ExpectedDescriptor:
    processor_id: int
    alias: bytes
    bitness: int
    register_count: int
    instruction_count: int
    return_code: int


EXPECTED = {
    "idaxmini": ExpectedDescriptor(0x8001, b"idaxmini", 64, 5, 1, 0),
    "xrisc32": ExpectedDescriptor(0x8100, b"xrisc32", 32, 18, 16, 14),
    "jbc": ExpectedDescriptor(0x8BC0, b"jbc", 32, 5, 256, 0x11),
}


def _runtime_library(ida_dir: Path) -> Path:
    if os.name == "nt":
        names = ("ida.dll", "ida64.dll", "libida.dll")
    elif sys.platform == "darwin":
        names = ("libida.dylib",)
    else:
        names = ("libida.so",)
    for name in names:
        candidate = ida_dir / name
        if candidate.is_file():
            return candidate
    raise ValidationError("matching IDA runtime library was not found under IDADIR")


def _decode_name(value: bytes | None, label: str) -> str:
    if not value:
        raise ValidationError(f"processor descriptor has an empty {label}")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError(f"processor descriptor has a non-UTF-8 {label}") from error


def _validate_descriptor(
    module_name: str,
    descriptor: ProcessorDescriptor,
    expected: ExpectedDescriptor,
) -> None:
    if descriptor.version <= 0:
        raise ValidationError(f"{module_name}: invalid interface version")
    if descriptor.id != expected.processor_id or descriptor.id <= 0x8000:
        raise ValidationError(f"{module_name}: incorrect third-party processor ID")
    if descriptor.cnbits != 8 or descriptor.dnbits != 8:
        raise ValidationError(f"{module_name}: incorrect code/data byte widths")
    if not descriptor.psnames or descriptor.psnames[0] != expected.alias:
        raise ValidationError(f"{module_name}: incorrect short processor alias")
    if descriptor.psnames[1]:
        raise ValidationError(f"{module_name}: unexpected extra short processor alias")
    if not descriptor.plnames:
        raise ValidationError(f"{module_name}: missing long processor names")
    _decode_name(descriptor.plnames[0], "long processor name")
    if not descriptor.assemblers or not descriptor.assemblers[0]:
        raise ValidationError(f"{module_name}: missing assembler descriptor")
    if descriptor.assemblers[1]:
        raise ValidationError(f"{module_name}: assembler array is not terminated")
    if not descriptor.notify:
        raise ValidationError(f"{module_name}: missing processor event callback")

    expected_bitness_flags = {
        16: 0,
        32: PR_USE32 | PR_DEFSEG32,
        64: PR_USE64 | PR_DEFSEG64,
    }[expected.bitness]
    actual_bitness_flags = descriptor.flag & (
        PR_USE32 | PR_DEFSEG32 | PR_USE64 | PR_DEFSEG64
    )
    if actual_bitness_flags != expected_bitness_flags:
        raise ValidationError(f"{module_name}: contradictory or incorrect bitness flags")

    if descriptor.regs_num != expected.register_count or not descriptor.reg_names:
        raise ValidationError(f"{module_name}: incorrect register table size")
    for index in range(descriptor.regs_num):
        _decode_name(descriptor.reg_names[index], f"register name {index}")
    segment_indices = (
        descriptor.reg_first_sreg,
        descriptor.reg_last_sreg,
        descriptor.reg_code_sreg,
        descriptor.reg_data_sreg,
    )
    if any(index < 0 or index >= descriptor.regs_num for index in segment_indices):
        raise ValidationError(f"{module_name}: segment-register index is out of range")
    if descriptor.reg_first_sreg > descriptor.reg_last_sreg:
        raise ValidationError(f"{module_name}: segment-register range is inverted")
    if descriptor.segreg_size < 0 or descriptor.segreg_size > 8:
        raise ValidationError(f"{module_name}: segment-register size is invalid")

    instruction_count = descriptor.instruc_end - descriptor.instruc_start
    if instruction_count != expected.instruction_count or not descriptor.instruc:
        raise ValidationError(f"{module_name}: incorrect instruction table size")
    for index in range(instruction_count):
        _decode_name(descriptor.instruc[index].name, f"instruction mnemonic {index}")
    if descriptor.icode_return != expected.return_code:
        raise ValidationError(f"{module_name}: incorrect return instruction code")
    if not (descriptor.instruc_start <= descriptor.icode_return < descriptor.instruc_end):
        raise ValidationError(f"{module_name}: return instruction code is out of range")


def validate_descriptors(build_dir: Path, ida_dir: Path) -> None:
    if not build_dir.is_dir():
        raise ValidationError("build directory does not exist")
    if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ProcessorDescriptor) != 144:
        raise ValidationError("descriptor validation requires the pinned 64-bit ABI")
    runtime_library = _runtime_library(ida_dir)
    directory_handle: object | None = None
    if os.name == "nt":
        add_directory = getattr(os, "add_dll_directory", None)
        if add_directory is not None:
            directory_handle = add_directory(str(ida_dir))
        runtime = ctypes.CDLL(str(runtime_library))
    else:
        runtime = ctypes.CDLL(str(runtime_library), mode=ctypes.RTLD_GLOBAL)

    loaded_modules: list[ctypes.CDLL] = []
    try:
        for module_name, expected in EXPECTED.items():
            module_path = find_module(build_dir, module_name)
            module = ctypes.CDLL(str(module_path))
            loaded_modules.append(module)
            try:
                descriptor = ProcessorDescriptor.in_dll(module, "LPH")
            except ValueError as error:
                raise ValidationError(f"{module_name}: exported LPH data was not found") from error
            _validate_descriptor(module_name, descriptor, expected)
            instruction_label = (
                "instruction" if expected.instruction_count == 1 else "instructions"
            )
            print(
                "processor descriptor: PASS "
                f"({module_path.name}: {expected.bitness}-bit, "
                f"{expected.register_count} registers, "
                f"{expected.instruction_count} {instruction_label})"
            )
    finally:
        # Keep native handles alive until every descriptor read is complete.
        _ = (runtime, loaded_modules)
        if directory_handle is not None:
            close = getattr(directory_handle, "close", None)
            if close is not None:
                close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("--ida-dir", type=Path, default=os.environ.get("IDADIR"))
    args = parser.parse_args()
    if args.ida_dir is None:
        print("error: IDADIR is required for descriptor validation", file=sys.stderr)
        return 1
    try:
        validate_descriptors(args.build_dir, args.ida_dir)
    except (OSError, ValidationError) as error:
        detail = _redact(str(error), (args.build_dir, args.ida_dir, Path.home()))
        print(f"error: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

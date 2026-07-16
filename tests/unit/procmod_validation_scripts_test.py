#!/usr/bin/env python3
"""Offline tests for processor-module export and runtime validation scripts."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import check_procmod_exports as exports  # noqa: E402
import check_procmod_descriptors as descriptors  # noqa: E402
import run_procmod_runtime_smoke as runtime  # noqa: E402


class ProcmodExportValidationTests(unittest.TestCase):
    def test_lph_pattern_accepts_platform_spellings(self) -> None:
        samples = (
            "0000000000000000 D LPH\n",
            "0000000000000000 S _LPH\n",
            "      1    0 00001000 LPH\n",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertIsNotNone(exports.LPH_PATTERN.search(sample))
        self.assertIsNone(exports.LPH_PATTERN.search("D LPH_helper\n"))

    def test_find_module_prefers_idabin_proc_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            build_dir = Path(raw_directory)
            preferred = build_dir / "idabin" / "procs" / "idaxmini.dylib"
            fallback = build_dir / "examples" / "idaxmini.dylib"
            preferred.parent.mkdir(parents=True)
            fallback.parent.mkdir(parents=True)
            preferred.touch()
            fallback.touch()
            self.assertEqual(exports.find_module(build_dir, "idaxmini"), preferred)

    def test_find_module_rejects_ambiguous_install_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            build_dir = Path(raw_directory)
            first = build_dir / "Debug" / "idabin" / "procs" / "idaxmini.dll"
            second = build_dir / "Release" / "idabin" / "procs" / "idaxmini.dll"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            first.touch()
            second.touch()
            with self.assertRaises(exports.ValidationError):
                exports.find_module(build_dir, "idaxmini")

    def test_redaction_removes_roots_and_license_identifiers(self) -> None:
        root = Path("sensitive") / "workspace"
        sensitive_path = str(root.resolve())
        redacted = exports._redact(
            f"{sensitive_path}/module 96-0000-0000-99", (root,)
        )
        self.assertNotIn(sensitive_path, redacted)
        self.assertNotIn("96-0000-0000-99", redacted)
        self.assertIn("<PATH>", redacted)
        self.assertIn("[REDACTED]", redacted)


class ProcmodRuntimeValidationTests(unittest.TestCase):
    def test_runtime_smoke_requires_rendered_mnemonic(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            build_dir = root / "build"
            module = build_dir / "idabin" / "procs" / "idaxmini.dylib"
            ida_dir = root / "ida"
            console = ida_dir / "idat"
            fixture = root / "fixture.bin"
            module.parent.mkdir(parents=True)
            ida_dir.mkdir()
            module.touch()
            console.touch()
            fixture.write_text("fixture", encoding="utf-8")

            def fake_run(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                log = Path(next(argument[2:] for argument in command if argument.startswith("-L")))
                database = Path(
                    next(argument[2:] for argument in command if argument.startswith("-o"))
                )
                self.assertEqual(Path(command[-1]).parent, kwargs["cwd"])
                log.write_text("processor initialized\n", encoding="utf-8")
                database.with_suffix(".asm").write_text("0000  nop\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(runtime.subprocess, "run", side_effect=fake_run):
                runtime.run_smoke(build_dir, ida_dir, fixture)

    def test_ida_console_rejects_missing_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            with self.assertRaises(exports.ValidationError):
                runtime._ida_console(Path(raw_directory))


class ProcmodDescriptorValidationTests(unittest.TestCase):
    def test_synthetic_descriptor_accepts_coherent_shape(self) -> None:
        names = (descriptors.ctypes.c_char_p * 2)(b"idaxmini", None)
        long_names = (descriptors.ctypes.c_char_p * 2)(b"Minimal", None)
        assemblers = (descriptors.ctypes.c_void_p * 2)(1, None)
        registers = (descriptors.ctypes.c_char_p * 5)(
            b"r0", b"sp", b"pc", b"cs", b"ds"
        )
        instructions = (descriptors.InstructionDescriptor * 1)(
            descriptors.InstructionDescriptor(b"nop", 0)
        )
        descriptor = descriptors.ProcessorDescriptor()
        descriptor.version = 1
        descriptor.id = 0x8001
        descriptor.flag = descriptors.PR_USE64 | descriptors.PR_DEFSEG64
        descriptor.cnbits = 8
        descriptor.dnbits = 8
        descriptor.psnames = names
        descriptor.plnames = long_names
        descriptor.assemblers = assemblers
        descriptor.notify = 1
        descriptor.reg_names = registers
        descriptor.regs_num = 5
        descriptor.reg_first_sreg = 3
        descriptor.reg_last_sreg = 4
        descriptor.reg_code_sreg = 3
        descriptor.reg_data_sreg = 4
        descriptor.instruc_start = 0
        descriptor.instruc_end = 1
        descriptor.instruc = instructions
        descriptor.icode_return = 0
        descriptors._validate_descriptor(
            "idaxmini", descriptor, descriptors.EXPECTED["idaxmini"]
        )

    def test_synthetic_descriptor_rejects_wrong_return_instruction(self) -> None:
        descriptor = descriptors.ProcessorDescriptor()
        descriptor.version = 1
        descriptor.id = 0x8001
        descriptor.flag = descriptors.PR_USE64 | descriptors.PR_DEFSEG64
        descriptor.cnbits = 8
        descriptor.dnbits = 8
        names = (descriptors.ctypes.c_char_p * 2)(b"idaxmini", None)
        long_names = (descriptors.ctypes.c_char_p * 2)(b"Minimal", None)
        assemblers = (descriptors.ctypes.c_void_p * 2)(1, None)
        registers = (descriptors.ctypes.c_char_p * 5)(
            b"r0", b"sp", b"pc", b"cs", b"ds"
        )
        instructions = (descriptors.InstructionDescriptor * 1)(
            descriptors.InstructionDescriptor(b"nop", 0)
        )
        descriptor.psnames = names
        descriptor.plnames = long_names
        descriptor.assemblers = assemblers
        descriptor.notify = 1
        descriptor.reg_names = registers
        descriptor.regs_num = 5
        descriptor.reg_first_sreg = 3
        descriptor.reg_last_sreg = 4
        descriptor.reg_code_sreg = 3
        descriptor.reg_data_sreg = 4
        descriptor.instruc_start = 0
        descriptor.instruc_end = 1
        descriptor.instruc = instructions
        descriptor.icode_return = 1
        with self.assertRaises(exports.ValidationError):
            descriptors._validate_descriptor(
                "idaxmini", descriptor, descriptors.EXPECTED["idaxmini"]
            )

    def test_synthetic_descriptor_rejects_contradictory_bitness(self) -> None:
        descriptor = descriptors.ProcessorDescriptor()
        descriptor.version = 1
        descriptor.id = 0x8001
        descriptor.flag = descriptors.PR_USE32 | descriptors.PR_USE64
        descriptor.cnbits = 8
        descriptor.dnbits = 8
        names = (descriptors.ctypes.c_char_p * 2)(b"idaxmini", None)
        descriptor.psnames = names
        with self.assertRaises(exports.ValidationError):
            descriptors._validate_descriptor(
                "idaxmini", descriptor, descriptors.EXPECTED["idaxmini"]
            )


if __name__ == "__main__":
    unittest.main()

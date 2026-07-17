from __future__ import annotations

from pathlib import Path

import pytest

import idax
from idax import (
    address,
    database,
    diagnostics,
    directory,
    exception,
    lines,
    loader,
    bookmark,
    parser,
    plugin,
    problem,
    processor,
    registry,
    registers,
    ui,
    undo,
    xref,
)


def test_package_contract() -> None:
    assert idax.__version__ == "0.1.0"
    assert idax.BAD_ADDRESS == 0xFFFF_FFFF_FFFF_FFFF
    assert idax.Address is int
    assert idax.AddressDelta is int
    assert idax.AddressSize is int
    assert undo.create_point.__name__ == "create_point"
    assert undo.undo_action_label.__name__ == "undo_action_label"
    with pytest.raises(idax.ValidationError, match="embedded NUL"):
        undo.create_point("bad\0action", "label")
    with pytest.raises(idax.ValidationError, match="embedded NUL"):
        undo.create_point("action", "bad\0label")
    assert problem.Kind.MISSING_OFFSET_BASE == 1
    assert problem.Kind.ATTENTION == 12
    assert problem.Kind.FLAIR_INDECISION == 16
    with pytest.raises(idax.ValidationError, match="embedded NUL"):
        problem.remember(problem.Kind.ATTENTION, 0, "bad\0message")
    assert bookmark.MAX_SLOTS == 1024
    with pytest.raises(idax.ValidationError, match="embedded NUL"):
        bookmark.set(0, "bad\0description")
    with pytest.raises(idax.ValidationError, match="outside the supported range"):
        bookmark.at_slot(bookmark.MAX_SLOTS)
    assert exception.CatchSelectorKind.TYPED.name == "TYPED"
    assert exception.SehDisposition.CONTINUE_SEARCH.name == "CONTINUE_SEARCH"
    assert exception.Location.CPP_TRY.name == "CPP_TRY"
    assert parser.Language.C.name == "C"
    assert parser.Language.OBJECTIVE_CPP.name == "OBJECTIVE_CPP"
    assert parser.InputKind.SOURCE_TEXT.name == "SOURCE_TEXT"
    parser_options = parser.ParseOptions()
    assert parser_options.input_kind is parser.InputKind.SOURCE_TEXT
    assert parser_options.pack_alignment == 0
    report = parser.ParseReport()
    assert report.ok
    assert bool(report)
    with pytest.raises(idax.ValidationError, match="embedded NUL"):
        parser.set_arguments("clang", "bad\0argument")
    assert directory.Kind.LOCAL_TYPES.value == 0
    assert directory.Kind.SNIPPETS.value == 7
    assert directory.EntryKind.DIRECTORY.name == "DIRECTORY"
    assert directory.OperationError.NOT_ORDERABLE.value == 9
    assert registry.ValueKind.STRING.value == 1
    assert registry.ValueKind.BINARY.value == 3
    assert registry.ValueKind.INTEGER.value == 4
    registry_update = registry.StringListUpdate()
    assert registry_update.max_records == 100
    assert not registry_update.ignore_case
    assert registers.TrackingState.UNDEFINED.name == "UNDEFINED"
    assert registers.TrackingState.STACK_POINTER_DELTA.name == "STACK_POINTER_DELTA"
    assert registers.ReferenceMutation.ADDED.name == "ADDED"
    assert registers.ReferenceMutation.REMOVED.name == "REMOVED"


def test_exception_models_are_opaque_python_values() -> None:
    metadata = exception.HandlerMetadata()
    metadata.regions = [address.Range(0x20, 0x24)]
    metadata.stack_displacement = -16
    metadata.frame_register = 5
    selector = exception.CatchSelector()
    selector.kind = exception.CatchSelectorKind.TYPED
    selector.type_identifier = 7
    handler = exception.CatchHandler()
    handler.metadata = metadata
    handler.object_displacement = -8
    handler.selector = selector
    handlers = exception.CppHandlers()
    handlers.catches = [handler]
    definition = exception.BlockDefinition()
    definition.protected_regions = [address.Range(0x10, 0x18)]
    definition.handlers = handlers
    assert definition.handlers.catches[0].selector.type_identifier == 7


def test_address_range_is_pythonic_value() -> None:
    value = address.Range(0x1000, 0x1010)
    assert value.start == 0x1000
    assert value.end == 0x1010
    assert value.size == 0x10
    assert len(value) == 0x10
    assert 0x1008 in value
    assert 0x1010 not in value
    assert bool(value)
    assert value == address.Range(0x1000, 0x1010)
    assert "Range" in repr(value)


def test_empty_address_range() -> None:
    value = address.Range(5, 5)
    assert value.empty
    assert not value
    assert len(value) == 0


def test_processor_id_normalization() -> None:
    assert database.processor_id_from_raw(0) is database.ProcessorId.INTEL_X86
    assert database.processor_id_from_raw(76) is database.ProcessorId.NDS32
    assert database.processor_id_from_raw(77) is None
    assert database.processor_id_from_raw(-1) is None


def test_pathlike_inputs(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    assert idax.path.basename(nested) == "nested"
    assert idax.path.dirname(nested) == str(tmp_path)
    assert idax.path.is_directory(nested)


def test_structured_exception_translation() -> None:
    diagnostics.reset_performance_counters()
    with pytest.raises(idax.InternalError) as caught:
        diagnostics.assert_invariant(False, "python binding invariant probe")
    error = caught.value
    assert isinstance(error, idax.IdaxError)
    assert error.category is idax.ErrorCategory.INTERNAL
    assert error.code == 0
    assert error.message == "Invariant failed"
    assert error.context == "python binding invariant probe"
    assert diagnostics.performance_counters().invariant_failures == 1


def test_error_info_enrichment() -> None:
    base = idax.ErrorInfo.validation("bad input", "parser")
    enriched = diagnostics.enrich(base, "python")
    assert enriched.category is idax.ErrorCategory.VALIDATION
    assert enriched.message == "bad input"
    assert enriched.context == "parser | python"


def test_tagged_text_and_reference_classification() -> None:
    tagged = lines.colstr("mov", lines.Color.INSTRUCTION)
    assert lines.tag_remove(tagged) == "mov"
    assert lines.tag_strlen(tagged) == 3
    assert lines.decode_addr_tag(lines.make_addr_tag(17), 0) == 17
    assert xref.is_call(xref.ReferenceType.CALL_NEAR)
    assert xref.is_jump(xref.ReferenceType.JUMP_FAR)
    assert xref.is_data_read(xref.ReferenceType.READ)
    assert not xref.is_data_write(xref.ReferenceType.READ)


def test_database_session_clean_close(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(database, "open", lambda *args: calls.append(("open", *args)))
    monkeypatch.setattr(database, "close", lambda save=False: calls.append(("close", save)))

    with database.opened("fixture.bin", save_on_exit=True) as session:
        assert session.is_open
    assert not session.is_open
    assert calls == [
        ("open", "fixture.bin", database.OpenMode.ANALYZE, database.LoadIntent.AUTO_DETECT),
        ("close", True),
    ]


def test_database_session_error_close(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(database, "open", lambda *args: calls.append(("open", *args)))
    monkeypatch.setattr(database, "close", lambda save=False: calls.append(("close", save)))

    with pytest.raises(LookupError):
        with database.opened("fixture.bin", save_on_exit=True, save_on_error=False):
            raise LookupError("probe")
    assert calls[-1] == ("close", False)


def test_database_session_explicit_close_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closes: list[bool] = []
    monkeypatch.setattr(database, "open", lambda *args: None)
    monkeypatch.setattr(database, "close", lambda save=False: closes.append(save))

    session = database.opened("fixture.bin")
    session.__enter__()
    session.close(save=True)
    session.close(save=False)
    assert closes == [True]


def test_loader_flag_round_trip() -> None:
    flags = loader.LoadFlags()
    fields = (
        "create_segments",
        "load_resources",
        "rename_entries",
        "manual_load",
        "fill_gaps",
        "create_import_segment",
        "first_file",
        "binary_code_segment",
        "reload",
        "auto_flat_group",
        "mini_database",
        "loader_options_dialog",
        "load_all_segments",
    )
    for field in fields:
        setattr(flags, field, True)
    decoded = loader.decode_load_flags(loader.encode_load_flags(flags))
    assert all(getattr(decoded, field) for field in fields)


def test_processor_sdk_flag_and_analysis_contract() -> None:
    assert int(processor.InstructionFeature.CHANGE7) == 0x020000
    assert int(processor.InstructionFeature.CHANGE8) == 0x040000
    assert int(processor.InstructionFeature.USE7) == 0x080000
    assert int(processor.InstructionFeature.USE8) == 0x100000
    assert int(processor.ProcessorFlag.HEX_NUMBERS) == 0
    assert int(processor.ProcessorFlag.DEFAULT_SEG32) == 0x000004
    assert int(processor.ProcessorFlag.USE64) == 0x002000
    assert int(processor.ProcessorFlag.USE_ARG_TYPES) == 0x200000
    assert int(processor.ProcessorFlag.CONDITIONAL_INSNS) == 0x4000000
    assert int(processor.ProcessorFlag2.CODE16_BIT) == 0x000008
    assert processor.AnalyzeDetails().instruction_code == 0


def test_plugin_and_processor_python_subclasses() -> None:
    class ProbePlugin(plugin.Plugin):
        def __init__(self) -> None:
            super().__init__()
            self.arguments: list[int] = []

        def info(self) -> plugin.Info:
            result = plugin.Info()
            result.name = "Python probe"
            return result

        def run(self, argument: int = 0) -> None:
            self.arguments.append(argument)

    extension = ProbePlugin()
    assert extension.info().name == "Python probe"
    extension.run(7)
    assert extension.arguments == [7]

    retained: list[processor.OutputContext] = []

    class ProbeProcessor(processor.Processor):
        def info(self) -> processor.ProcessorInfo:
            return processor.ProcessorInfo()

        def analyze(self, address: int) -> int:
            return 4

        def emulate(self, address: int) -> processor.EmulateResult:
            return processor.EmulateResult.SUCCESS

        def output_instruction(self, address: int) -> None:
            pass

        def output_operand(
            self, address: int, operand_index: int
        ) -> processor.OutputOperandResult:
            return processor.OutputOperandResult.SUCCESS

        def output_instruction_with_context(
            self, address: int, output: processor.OutputContext
        ) -> processor.OutputInstructionResult:
            retained.append(output)
            output.mnemonic("probe").space().immediate(address)
            return processor.OutputInstructionResult.SUCCESS

    proc = ProbeProcessor()
    output = processor.OutputContext()
    assert (
        processor.Processor.output_instruction_with_context(proc, 0x20, output)
        is processor.OutputInstructionResult.SUCCESS
    )
    assert output.text == "probe 0x20"
    with pytest.raises(idax.ConflictError):
        retained[0].append("expired")


def test_ui_form_builder_owns_mutable_field_state() -> None:
    builder = ui.form_builder("Python form")
    integer = builder.add_int("Value", 7)
    text = builder.add_text("Label", "idax")
    choices = builder.add_radio("Mode", 1, ["First", "Second"])

    assert integer.value == 7
    assert text.value == "idax"
    assert choices.value == 1
    assert builder.bindings == [integer, text, choices]
    assert "Value" in builder.markup
    assert "##Mode##First:R>" in builder.markup

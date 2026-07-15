from __future__ import annotations

import os
import shutil
import threading
import uuid
import warnings
from pathlib import Path

import pytest

from idax import (
    ConflictError,
    IdaxError,
    address,
    analysis,
    comment,
    data,
    database,
    debugger,
    decompiler,
    entry,
    event,
    fixup,
    function,
    graph,
    instruction,
    loader,
    lumina,
    name,
    plugin,
    processor,
    search,
    segment,
    storage,
    type,
    ui,
    xref,
)


@pytest.mark.ida_runtime
def test_ida_94_database_lifecycle_and_thread_affinity(tmp_path: Path) -> None:
    source_text = os.environ.get("IDAX_PYTHON_RUNTIME_FIXTURE")
    if not source_text:
        pytest.skip("IDAX_PYTHON_RUNTIME_FIXTURE is not configured")

    source = Path(source_text)
    copied_input = tmp_path / source.name
    shutil.copy2(source, copied_input)
    companion_database = source.with_name(f"{source.name}.i64")
    if companion_database.is_file():
        fixture = tmp_path / companion_database.name
        shutil.copy2(companion_database, fixture)
    else:
        fixture = copied_input

    options = database.RuntimeOptions(
        quiet=True,
        plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True),
    )
    database.init(["idax-python-runtime-test"], options)
    database.open(fixture, database.OpenMode.SKIP_ANALYSIS)
    try:
        bounds = database.address_bounds()
        assert bounds.start < bounds.end
        assert database.address_bitness() in (16, 32, 64)
        assert database.processor() is database.ProcessorId.INTEL_X86
        assert len(database.input_md5()) == 32
        assert address.next_mapped(bounds.start) <= bounds.end
        assert isinstance(analysis.is_enabled(), bool)
        segments = list(segment.all())
        assert len(segments) == segment.count()
        assert segments
        assert segment.first().start == segments[0].start
        assert segment.at(segments[0].start).name == segments[0].name
        assert len(name.all()) >= len(name.all_user_defined())
        assert search.next_defined(bounds.start) <= bounds.end
        assert isinstance(xref.refs_from(bounds.start), list)
        assert isinstance(lumina.has_connection(), bool)
        entry_count = entry.count()
        if entry_count:
            assert isinstance(entry.by_index(0).ordinal, int)

        functions = list(function.all())
        assert len(functions) == function.count()
        if functions:
            first_function = functions[0]
            assert function.at(first_function.start).start == first_function.start
            assert function.by_index(0).start == first_function.start
            assert function.item_addresses(first_function.start)

        code_address = search.next_code(bounds.start)
        decoded = instruction.decode(code_address)
        assert decoded.address == code_address
        assert decoded.size > 0
        assert instruction.text(code_address)
        assert data.read_bytes(code_address, decoded.size)
        assert isinstance(list(fixup.all()), list)

        parsed_type = type.TypeInfo.from_declaration("int idax_python_value")
        assert parsed_type.is_integer
        assert parsed_type.size == 4

        custom_graph = graph.Graph()
        graph_first = custom_graph.add_node()
        graph_second = custom_graph.add_node()
        custom_graph.add_edge(graph_first, graph_second)
        assert custom_graph.successors(graph_first) == [graph_second]
        assert custom_graph.predecessors(graph_second) == [graph_first]
        assert custom_graph.path_exists(graph_first, graph_second)
        assert len(custom_graph.edges()) == 1
        custom_graph.remove_edge(graph_first, graph_second)
        custom_graph.clear()
        if functions:
            assert graph.flowchart(functions[0].start)

            decompiler_available = decompiler.available()
            if not decompiler_available:
                if os.environ.get("IDAX_PYTHON_REQUIRE_DECOMPILER") == "1":
                    pytest.fail(
                        "a compatible Hex-Rays decompiler is required but unavailable"
                    )
                warnings.warn(
                    "compatible Hex-Rays decompiler unavailable; "
                    "decompiler runtime tranche not executed",
                    RuntimeWarning,
                    stacklevel=1,
                )
            else:
                decompiled: decompiler.DecompiledFunction | None = None
                decompiled_address = 0
                for candidate in functions:
                    try:
                        decompiled = decompiler.decompile(candidate.start)
                        decompiled_address = candidate.start
                        break
                    except IdaxError:
                        continue
                assert decompiled is not None
                assert decompiled.entry_address == decompiled_address
                assert decompiled.pseudocode()
                assert decompiled.lines()
                assert decompiled.declaration()
                assert len(decompiled.variables()) == decompiled.variable_count()
                assert decompiler.view_for_function(
                    decompiled_address
                ).function_address == decompiled_address
                assert isinstance(
                    decompiler.collect_referenced_types(decompiled_address).ordinals,
                    list,
                )

                retained_expressions: list[decompiler.ExpressionView] = []
                expression_count = decompiler.for_each_expression(
                    decompiled,
                    lambda expression: (
                        retained_expressions.append(expression)
                        or decompiler.VisitAction.CONTINUE
                    ),
                )
                assert expression_count > 0
                assert retained_expressions
                with pytest.raises(ConflictError):
                    retained_expressions[0].to_string()

                retained_contexts: list[decompiler.MicrocodeContext] = []

                class ProbeFilter(decompiler.MicrocodeFilter):
                    def match(self, context: decompiler.MicrocodeContext) -> bool:
                        retained_contexts.append(context)
                        return False

                    def apply(
                        self, context: decompiler.MicrocodeContext
                    ) -> decompiler.MicrocodeApplyResult:
                        return decompiler.MicrocodeApplyResult.NOT_HANDLED

                filter_token = decompiler.register_microcode_filter(ProbeFilter())
                with decompiler.ScopedMicrocodeFilter(filter_token):
                    microcode = decompiler.generate_microcode(decompiled_address)
                    assert microcode.entry_address == decompiled_address
                    assert microcode.blocks
                assert retained_contexts
                with pytest.raises(ConflictError):
                    retained_contexts[0].local_variable_count()
                decompiled.close()
                assert not decompiled.valid
                with pytest.raises(ConflictError):
                    decompiled.pseudocode()

        assert isinstance(debugger.available_backends(), list)
        assert isinstance(debugger.is_request_running(), bool)

        class EchoExecutor(debugger.AppcallExecutor):
            def execute(
                self, request: debugger.AppcallRequest
            ) -> debugger.AppcallResult:
                result = debugger.AppcallResult()
                result.return_value.kind = debugger.AppcallValueKind.SIGNED_INTEGER
                result.return_value.signed_value = len(request.arguments)
                result.diagnostics = "python executor"
                return result

        executor_name = f"idax-python-{uuid.uuid4().hex}"
        appcall_request = debugger.AppcallRequest()
        appcall_request.function_type = type.TypeInfo.function_type(type.TypeInfo.int32())
        appcall_request.arguments = [debugger.AppcallValue()]
        debugger.register_executor(executor_name, EchoExecutor())
        try:
            appcall_result = debugger.appcall_with_executor(
                executor_name, appcall_request
            )
            assert appcall_result.return_value.signed_value == 1
            assert appcall_result.diagnostics == "python executor"
        finally:
            debugger.unregister_executor(executor_name)

        action_calls: list[str] = []
        action = plugin.Action()
        action.id = f"idax:python:{uuid.uuid4().hex}"
        action.label = "IDAX Python runtime probe"
        action.handler = lambda: action_calls.append("action")
        action.enabled = lambda: True
        plugin.register_action(action)
        plugin.unregister_action(action.id)
        assert action_calls == []

        hotkey_calls: list[str] = []
        hotkey = plugin.register_hotkey(
            "Ctrl-Shift-F12", lambda: hotkey_calls.append("hotkey")
        )
        with hotkey:
            assert hotkey.active
        assert not hotkey.active
        assert hotkey_calls == []

        assert loader.encode_load_flags(loader.decode_load_flags(0)) == 0
        output = processor.OutputContext()
        assert output.mnemonic("mov").space().register_name("x0").text == "mov x0"
        current_widget = ui.current_widget()
        assert ui.widget_type(current_widget) is ui.WidgetType.UNKNOWN
        assert isinstance(ui.clipboard_backend(), str)
        assert ui.user_directory()
        ui_token = ui.on_event(lambda _ui_event: None)
        ui.unsubscribe(ui_token)

        node = storage.Node.open(f"$idax_python_{uuid.uuid4().hex}", create=True)
        node.set_alt(1, 0x1234)
        node.set_sup(2, b"idax-sup")
        node.set_hash("key", "value")
        node.set_blob(3, memoryview(b"idax-blob"))
        assert node.alt(1) == 0x1234
        assert node.sup(2) == b"idax-sup"
        assert node.hash("key") == "value"
        assert node.blob(3) == b"idax-blob"
        node.remove_alt(1)
        node.remove_blob(3)

        comment_events: list[tuple[int, bool]] = []
        subscription = event.ScopedSubscription(
            event.on_comment_changed(
                lambda event_address, repeatable: comment_events.append(
                    (event_address, repeatable)
                )
            )
        )
        assert subscription.token != 0
        with subscription:
            comment.set(code_address, "idax Python callback probe")
        assert (code_address, False) in comment_events
        comment.remove(code_address)

        patched_events: list[tuple[int, int]] = []
        patch_token = event.on_byte_patched(
            lambda event_address, old_value: patched_events.append(
                (event_address, old_value)
            )
        )
        original = data.read_byte(code_address)
        try:
            data.patch_byte(code_address, original ^ 0xFF)
            assert data.read_byte(code_address) == (original ^ 0xFF)
            assert data.original_byte(code_address) == original
            assert any(item[0] == code_address for item in patched_events)
        finally:
            data.revert_patch(code_address)
            event.unsubscribe(patch_token)
        assert data.read_byte(code_address) == original

        suffix = uuid.uuid4().hex
        type_definition = data.CustomDataTypeDefinition()
        type_definition.name = f"idax_python_u16_{suffix}"
        type_definition.menu_name = "IDAX Python u16"
        type_definition.assembler_keyword = "idax_py_u16"
        type_definition.value_size = 2
        type_definition.allow_duplicates = False
        type_definition.may_create_at = lambda _address, length: length == 2

        format_definition = data.CustomDataFormatDefinition()
        format_definition.name = f"idax_python_u16_format_{suffix}"
        format_definition.menu_name = "IDAX Python u16 format"
        format_definition.value_size = 2
        format_definition.text_width = 8
        format_definition.render = lambda value, _context: str(
            int.from_bytes(value, "little")
        )
        format_definition.scan = lambda text, _context: int(text).to_bytes(
            2, "little"
        )
        analyzed: list[int] = []
        format_definition.analyze = lambda context: analyzed.append(context.address)

        custom_type = data.register_custom_data_type(type_definition)
        custom_format = data.register_custom_data_format(format_definition)
        try:
            context = data.CustomDataFormatContext()
            context.address = code_address
            context.type_id = custom_type
            assert data.find_custom_data_type(type_definition.name) == custom_type
            assert data.find_custom_data_format(format_definition.name) == custom_format
            assert data.render_custom_data(custom_format, b"4\x12", context) == "4660"
            assert data.scan_custom_data(custom_format, "4660", context) == b"4\x12"
            data.analyze_custom_data(custom_format, context)
            assert analyzed == [code_address]
        finally:
            data.unregister_custom_data_format(custom_format)
            data.unregister_custom_data_type(custom_type)

        observed: list[BaseException] = []

        def cross_thread_call() -> None:
            try:
                database.image_base()
            except BaseException as error:
                observed.append(error)

        worker = threading.Thread(target=cross_thread_call)
        worker.start()
        worker.join()

        assert len(observed) == 1
        assert isinstance(observed[0], ConflictError)
        assert "initializing thread" in str(observed[0])
    finally:
        database.close(False)

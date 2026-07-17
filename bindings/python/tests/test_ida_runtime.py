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
    NotFoundError,
    ValidationError,
    address,
    analysis,
    bookmark,
    navigation,
    comment,
    data,
    database,
    debugger,
    decompiler,
    directory,
    entry,
    event,
    exception,
    fixup,
    function,
    graph,
    instruction,
    loader,
    lumina,
    name,
    plugin,
    processor,
    parser,
    problem,
    registry,
    search,
    segment,
    storage,
    type,
    ui,
    undo,
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
    fixture = copied_input

    options = database.RuntimeOptions(
        quiet=True,
        plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True),
    )
    database.init(["idax-python-runtime-test"], options)
    database.open(fixture, database.OpenMode.ANALYZE)
    try:
        analysis.wait()
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
        segment_registers = segment.segment_registers()
        assert segment_registers
        assert all(value.name and value.bit_width > 0
                   for value in segment_registers)
        assert any(value.is_code for value in segment_registers)
        assert any(value.is_data for value in segment_registers)
        segment_register = segment_registers[0]
        segment_address = segments[0].start
        effective_value = segment.segment_register_value(
            segment_address, segment_register.name)
        assert effective_value is None or isinstance(effective_value, int)
        default_value = segment.default_segment_register_value(
            segment_address, segment_register.name)
        register_range = segment.segment_register_range(
            segment_address, segment_register.name)
        assert register_range.start <= segment_address < register_range.end
        assert register_range.source in tuple(segment.SegmentRegisterSource)
        assert segment.segment_register_ranges(segment_register.name)
        assert segment.segment_register_range_index(
            segment_address, segment_register.name) is not None
        segment.set_default_segment_register(
            segment_address, segment_register.name, 0x234)
        assert segment.default_segment_register_value(
            segment_address, segment_register.name) == 0x234
        segment.set_default_segment_register(
            segment_address, segment_register.name, default_value)
        with pytest.raises(ValidationError):
            segment.segment_register_value(segment_address, "bad\0name")
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

            try:
                original_repeatable = comment.get(first_function.start, True)
            except NotFoundError:
                original_repeatable = None
            undo_label = "IDAX Python undo round-trip π"
            assert undo.create_point("idax.python.undo", undo_label)
            comment.set(first_function.start, "idax python undo mutation", True)
            assert undo.undo_action_label() == undo_label
            assert undo.perform_undo()
            if original_repeatable is None:
                with pytest.raises(NotFoundError):
                    comment.get(first_function.start, True)
            else:
                assert comment.get(first_function.start, True) == original_repeatable
            assert undo.redo_action_label() == undo_label
            assert undo.perform_redo()
            assert comment.get(first_function.start, True) == "idax python undo mutation"
            assert undo.perform_undo()
            if original_repeatable is None:
                with pytest.raises(NotFoundError):
                    comment.get(first_function.start, True)
            else:
                assert comment.get(first_function.start, True) == original_repeatable

            problem_kind = problem.Kind.ATTENTION
            problem.remove(problem_kind, first_function.start)
            assert not problem.contains(problem_kind, first_function.start)
            assert problem.description(problem_kind, first_function.start) is None
            assert problem.name(problem_kind, True)
            assert problem.name(problem_kind, False)
            problem_message = "IDAX Python problem round-trip π"
            problem.remember(problem_kind, first_function.start, problem_message)
            assert problem.contains(problem_kind, first_function.start)
            assert problem.description(problem_kind, first_function.start) == problem_message
            assert problem.next(problem_kind, first_function.start) == first_function.start
            assert problem.remove(problem_kind, first_function.start)
            assert not problem.remove(problem_kind, first_function.start)
            assert not problem.contains(problem_kind, first_function.start)
            assert problem.description(problem_kind, first_function.start) is None
            assert problem.next(problem_kind, first_function.start) != first_function.start

            bookmark_addresses = function.code_addresses(first_function.start)
            if len(bookmark_addresses) >= 2:
                bookmark_address = next(
                    (value for value in bookmark_addresses if bookmark.at(value) is None),
                    None,
                )
                assert bookmark_address is not None
                occupied_slots = {value.slot for value in bookmark.all()}
                bookmark_slot = next(
                    (
                        slot
                        for slot in range(29, bookmark.MAX_SLOTS)
                        if slot not in occupied_slots
                    ),
                    None,
                )
                assert bookmark_slot is not None
                created_bookmark = bookmark.set(
                    bookmark_address, "IDAX Python bookmark π", bookmark_slot
                )
                try:
                    assert created_bookmark.address == bookmark_address
                    assert created_bookmark.slot == bookmark_slot
                    assert created_bookmark.description == "IDAX Python bookmark π"
                    assert bookmark.at(bookmark_address).slot == bookmark_slot
                    assert bookmark.at_slot(bookmark_slot).address == bookmark_address
                    updated_bookmark = bookmark.set(
                        bookmark_address, "IDAX Python updated λ"
                    )
                    assert updated_bookmark.slot == bookmark_slot
                    assert updated_bookmark.description == "IDAX Python updated λ"
                    conflict_slot = 1 if bookmark_slot == 0 else 0
                    with pytest.raises(ConflictError, match="different slot"):
                        bookmark.set(bookmark_address, "conflict", conflict_slot)
                    assert bookmark.remove_slot(bookmark_slot)
                    assert not bookmark.remove_slot(bookmark_slot)
                    assert bookmark.at(bookmark_address) is None
                finally:
                    bookmark.remove(bookmark_address)

            navigation_addresses = function.code_addresses(first_function.start)
            if len(navigation_addresses) >= 5:
                def navigation_entry(
                    index: int, channel: str, metadata: str
                ) -> navigation.Entry:
                    value = navigation.Entry()
                    value.address = navigation_addresses[index]
                    value.channel = channel
                    value.metadata = metadata
                    return value

                alpha0 = navigation_entry(0, "alpha", "a0 π")
                alpha1 = navigation_entry(1, "alpha", "a1")
                beta0 = navigation_entry(2, "beta", "b0")
                other0 = navigation_entry(3, "other", "o0")
                gamma0 = navigation_entry(4, "gamma", "g0")
                stream_suffix = uuid.uuid4().hex
                history = navigation.open(
                    f"python-phase68-main-{stream_suffix}", alpha0
                )
                assert history.created
                assert history.entries == [alpha0]
                assert history.current == alpha0
                assert history.index == 0
                history.set_current(beta0)
                assert history.current_for("beta") == beta0
                assert history.push(alpha1) == alpha1
                assert history.back() == alpha0
                assert history.forward() == alpha1
                assert history.forward() is None
                history.replace(0, other0)
                assert history.seek(0) == other0
                destination = navigation.open(
                    f"python-phase68-destination-{stream_suffix}", gamma0
                )
                history.transfer_channel_to(destination, "alpha", True)
                assert history.entries == [other0]
                assert history.current_for("alpha") is None
                assert destination.entries == [gamma0, alpha1]
                assert destination.current_for("alpha") == alpha1
                assert all(
                    not value.channel.startswith("$ idax navigation/")
                    for value in destination.all_current
                )
                reopened = navigation.open(
                    f"python-phase68-main-{stream_suffix}", alpha0
                )
                assert not reopened.created
                assert reopened.entries == [other0]

            parser.select_for([parser.Language.C, parser.Language.CPP])
            parser_name = parser.selected_name()
            assert parser_name
            parser.set_arguments(parser_name, "")
            conflicting_options = parser.ParseOptions()
            conflicting_options.assume_high_level = True
            conflicting_options.lower_prototypes = True
            with pytest.raises(ValidationError, match="mutually exclusive"):
                parser.parse_with_options(
                    parser_name,
                    "struct idax_python_parser_conflicting_modes { int value; };",
                    conflicting_options,
                )
            syntax_report = parser.parse_with(
                parser_name, "struct idax_python_parser_syntax_error {"
            )
            assert not syntax_report.ok
            assert syntax_report.error_count > 0
            memory_report = parser.parse_for(
                parser.Language.C,
                "struct idax_python_parser_memory { int value; };",
            )
            assert memory_report.ok
            assert type.TypeInfo.by_name("idax_python_parser_memory").is_struct

            named_report = parser.parse_with(
                parser_name,
                "struct idax_python_parser_named { unsigned value; };",
            )
            assert named_report.ok
            assert type.TypeInfo.by_name("idax_python_parser_named").is_struct

            parser_options = parser.ParseOptions()
            parser_options.allow_redeclarations = True
            parser_options.suppress_warnings = True
            parser_options.pack_alignment = 4
            extended_report = parser.parse_with_options(
                parser_name,
                "struct idax_python_parser_extended { char value; };",
                parser_options,
            )
            assert extended_report.ok
            assert type.TypeInfo.by_name("idax_python_parser_extended").is_struct

            parser_source = tmp_path / "idax_python_parser_input.hpp"
            parser_source.write_text(
                "struct idax_python_parser_file { long long value; };\n",
                encoding="utf-8",
            )
            file_report = parser.parse_for(
                parser.Language.CPP,
                str(parser_source),
                parser.InputKind.FILE_PATH,
            )
            parser_source.unlink()
            assert file_report.ok
            assert type.TypeInfo.by_name("idax_python_parser_file").is_struct

            option_value = parser.option(parser_name, "CLANG_APPLY_TINFO")
            parser.set_option(parser_name, "CLANG_APPLY_TINFO", option_value)
            assert parser.option(parser_name, "CLANG_APPLY_TINFO") == option_value
            parser.select()
            default_parser_name = parser.selected_name()
            assert default_parser_name is None or default_parser_name

            directory_kinds = (
                directory.Kind.LOCAL_TYPES,
                directory.Kind.FUNCTIONS,
                directory.Kind.NAMES,
                directory.Kind.IMPORTS,
                directory.Kind.IDA_PLACE_BOOKMARKS,
                directory.Kind.BREAKPOINTS,
                directory.Kind.LOCAL_TYPE_BOOKMARKS,
                directory.Kind.SNIPPETS,
            )
            for directory_kind in directory_kinds:
                candidate_tree = directory.Tree.open(directory_kind)
                assert candidate_tree.kind is directory_kind
                assert candidate_tree.entry("/").is_directory
                assert isinstance(candidate_tree.children(), list)

            directory_tree = directory.Tree.open(directory.Kind.FUNCTIONS)
            with pytest.raises(ValidationError, match="embedded NUL"):
                directory_tree.contains("bad\0path")
            with pytest.raises(ValidationError, match="cannot be empty"):
                directory_tree.move([], "/")
            directory_tree.change_directory("/")
            assert directory_tree.current_directory == "/"
            assert (
                directory_tree.absolute_path("idax_python_directory_probe")
                == "/idax_python_directory_probe"
            )

            directory_alpha = "/idax_python_directory_alpha"
            directory_child = "/idax_python_directory_alpha/child"
            directory_renamed = "/idax_python_directory_alpha/renamed"
            directory_beta = "/idax_python_directory_beta"
            directory_destination = "/idax_python_directory_destination"
            directory_empty = "/idax_python_directory_empty"
            directory_native_parent = "/idax_python_directory_native_parent"
            directory_native_valid = "/idax_python_directory_native_valid"
            directory_native_destination = (
                "/idax_python_directory_native_parent/child"
            )
            directory_fold_root = "/idax_python_directory_fold"
            directory_fold_child = "/idax_python_directory_fold/a"
            directory_fold_grandchild = "/idax_python_directory_fold/a/b"
            directory_tree.create_directory(directory_alpha)
            directory_tree.create_directory(directory_child)
            directory_tree.create_directory(directory_beta)
            directory_tree.create_directory(directory_destination)
            directory_tree.create_directory(directory_empty)
            directory_tree.remove_directory(directory_empty)
            assert not directory_tree.contains(directory_empty)
            directory_tree.create_directory(directory_native_parent)
            directory_tree.create_directory(directory_native_valid)
            directory_tree.create_directory(directory_native_destination)
            native_rejected = directory_tree.move(
                [
                    "/__idax_python_directory_missing_native_reject__",
                    directory_native_parent,
                    directory_native_valid,
                ],
                directory_native_destination,
            )
            assert native_rejected.affected_paths == [
                "/idax_python_directory_native_parent/child/"
                "idax_python_directory_native_valid"
            ]
            assert [failure.input_index for failure in native_rejected.failures] == [
                0,
                1,
            ]
            assert (
                native_rejected.failures[0].error
                is directory.OperationError.NOT_FOUND
            )
            assert (
                native_rejected.failures[1].error
                is directory.OperationError.OWN_CHILD
            )
            assert directory_tree.remove([directory_native_parent]).ok
            directory_tree.create_directory(directory_fold_root)
            directory_tree.create_directory(directory_fold_child)
            directory_tree.create_directory(directory_fold_grandchild)
            directory_tree.fold_common_prefix(directory_fold_root)
            folded_children = directory_tree.children(directory_fold_root)
            assert len(folded_children) == 1
            assert folded_children[0].is_directory
            assert "\x1d" in folded_children[0].name
            assert directory_tree.remove([directory_fold_root]).ok
            with pytest.raises(ConflictError, match="already exists"):
                directory_tree.create_directory(directory_alpha)
            assert directory_tree.entry(directory_alpha).is_directory
            assert any(
                item.path == directory_child
                for item in directory_tree.children(directory_alpha)
            )
            directory_tree.rename(directory_child, directory_renamed)
            assert not directory_tree.contains(directory_child)
            assert directory_tree.contains(directory_renamed)
            assert any(
                item.path == directory_renamed
                for item in directory_tree.snapshot(directory_alpha)
            )
            assert directory_tree.find_items("*")

            directory_item = next(
                item
                for item in directory_tree.children("/")
                if not item.is_directory
            )
            directory_tree.unlink(directory_item.path)
            assert not directory_tree.contains(directory_item.path)
            directory_tree.link(directory_item.name)
            assert directory_tree.contains(directory_item.path)

            if directory_tree.is_orderable:
                natural_order = directory_tree.has_natural_order("/")
                directory_tree.set_natural_order("/", not natural_order)
                directory_tree.set_natural_order("/", natural_order)
                assert isinstance(directory_tree.rank(directory_alpha), int)
                directory_tree.change_rank(directory_alpha, 1)
                directory_tree.change_rank(directory_alpha, -1)

            moved_directories = directory_tree.move(
                [
                    "/__idax_python_directory_missing_move_a__",
                    directory_alpha,
                    "/__idax_python_directory_missing_move_b__",
                    directory_beta,
                ],
                directory_destination,
            )
            assert not moved_directories.ok
            assert len(moved_directories.affected_paths) == 2
            assert len(moved_directories.failures) == 2
            assert moved_directories.failures[0].input_index == 0
            assert (
                moved_directories.failures[0].error
                is directory.OperationError.NOT_FOUND
            )
            assert moved_directories.failures[1].input_index == 2
            assert (
                moved_directories.failures[1].error
                is directory.OperationError.NOT_FOUND
            )

            removed_directories = directory_tree.remove(
                [
                    "/__idax_python_directory_missing_remove_a__",
                    directory_destination,
                    "/__idax_python_directory_missing_remove_b__",
                ]
            )
            assert not removed_directories.ok
            assert removed_directories.affected_paths == [directory_destination]
            assert len(removed_directories.failures) == 2
            assert removed_directories.failures[0].input_index == 0
            assert removed_directories.failures[1].input_index == 2
            assert not directory_tree.contains(directory_destination)

            registry_store = registry.Store.open(
                f"idax\\phase64\\python_{uuid.uuid4().hex}"
            )
            registry_store.erase_tree()
            assert not registry_store.exists
            assert registry_store.value_kind("missing") is None
            assert registry_store.read_string("missing") is None
            with pytest.raises(ValidationError, match="one path component"):
                registry_store.child("bad/path")

            registry_store.write_string("text", "python registry π")
            registry_store.write_binary("binary", bytes([0, 1, 127, 128, 255]))
            registry_store.write_binary("empty_binary", b"")
            registry_store.write_integer("integer", -(1 << 31))
            registry_store.write_boolean("enabled", True)
            registry_store.write_boolean("disabled", False)
            assert registry_store.read_string("text") == "python registry π"
            assert registry_store.read_binary("binary") == bytes(
                [0, 1, 127, 128, 255]
            )
            assert registry_store.read_binary("empty_binary") == b""
            assert registry_store.read_integer("integer") == -(1 << 31)
            assert registry_store.read_boolean("enabled") is True
            assert registry_store.read_boolean("disabled") is False
            with pytest.raises(ConflictError, match="kind"):
                registry_store.read_binary("text")
            assert registry_store.value_kind("text") is registry.ValueKind.STRING
            assert registry_store.value_kind("binary") is registry.ValueKind.BINARY
            assert registry_store.value_kind("integer") is registry.ValueKind.INTEGER
            assert registry_store.value_kind("enabled") is registry.ValueKind.INTEGER
            assert {"text", "binary", "integer", "enabled"}.issubset(
                registry_store.value_names()
            )

            registry_child = registry_store.child("child")
            registry_child.write_string("nested", "value")
            assert "child" in registry_store.child_keys()
            registry_list = registry_store.child("list")
            with pytest.raises(ValidationError, match="embedded NUL"):
                registry_list.write_string_list(["bad\0value"])
            registry_list.write_string_list(["alpha", "beta", "gamma"])
            list_update = registry.StringListUpdate()
            list_update.add = "delta"
            list_update.remove = "beta"
            list_update.max_records = 3
            registry_list.update_string_list(list_update)
            assert registry_list.read_string_list() == ["delta", "alpha", "gamma"]
            contradictory_update = registry.StringListUpdate()
            contradictory_update.add = "same"
            contradictory_update.remove = "SAME"
            contradictory_update.ignore_case = True
            with pytest.raises(ValidationError, match="same value"):
                registry_list.update_string_list(contradictory_update)
            registry_list.write_string_list([])
            assert registry_list.read_string_list() == []

            assert not registry_store.erase_key()
            assert registry_store.erase_value("text")
            assert not registry_store.erase_value("text")
            assert registry_store.erase_tree()
            assert not registry_store.exists

            exception_heads = None
            for candidate in functions:
                addresses = function.code_addresses(candidate.start)
                if len(addresses) >= 5:
                    exception_heads = addresses[:5]
                    break
            if exception_heads is not None:
                scope = address.Range(exception_heads[0], exception_heads[4])
                exception.remove(scope)
                metadata = exception.HandlerMetadata()
                metadata.regions = [
                    address.Range(exception_heads[2], exception_heads[3])
                ]
                metadata.stack_displacement = 16
                metadata.frame_register = 5
                selector = exception.CatchSelector()
                selector.kind = exception.CatchSelectorKind.TYPED
                selector.type_identifier = 7
                handler = exception.CatchHandler()
                handler.metadata = metadata
                handler.object_displacement = 24
                handler.selector = selector
                handlers = exception.CppHandlers()
                handlers.catches = [handler]
                definition = exception.BlockDefinition()
                definition.protected_regions = [
                    address.Range(exception_heads[0], exception_heads[1])
                ]
                definition.handlers = handlers
                try:
                    exception.add(definition)
                    blocks = exception.list(scope)
                    block = next(
                        item for item in blocks
                        if item.definition.protected_regions[0].start
                        == exception_heads[0]
                    )
                    assert block.definition.handlers.catches[0].selector.type_identifier == 7
                    assert exception.contains(
                        exception_heads[0], exception.Location.CPP_TRY
                    )
                    assert exception.contains(
                        exception_heads[2], [exception.Location.CPP_HANDLER]
                    )
                    system_start = exception.system_region_start(exception_heads[0])
                    assert system_start is None or isinstance(system_start, int)
                finally:
                    exception.remove(scope)
                assert not exception.contains(exception_heads[0])

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

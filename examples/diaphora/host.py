"""Audited Diaphora feature bodies hosted by public, opaque IDAX operations.

The compatibility records below are private owned Python values. They neither
import SDK modules nor install replacement modules in sys.modules.
"""

from __future__ import annotations

import ast
import decimal
import importlib
import json
import math
import os
from pathlib import Path
import re
import sys
import time
import traceback
import sqlite3
from collections import Counter
from hashlib import md5
from types import SimpleNamespace

import idax
from idax import address, comment, data, database, decompiler, function
from idax import graph, instruction, lines, name, script, segment, type as types, ui

from .backend import engine_class, load_backend, upstream_definitions, verify_upstream


def _idc(function_name, *arguments):
    result = script.call(function_name, [script.Value(value) for value in arguments])
    if not result:
        raise RuntimeError(f"{function_name}: {result.error}")
    value = result.value
    if value.kind == script.ValueKind.STRING:
        return value.as_string()
    if value.kind == script.ValueKind.INTEGER:
        return value.as_integer()
    raise RuntimeError(f"Unexpected result kind for {function_name}")


def _optional(operation, *arguments):
    try:
        return operation(*arguments)
    except idax.NotFoundError:
        return None


def _function(ea):
    value = _optional(function.at, int(ea))
    if value is None:
        return None
    return SimpleNamespace(start_ea=value.start, end_ea=value.end)


def _segment_start(ea):
    value = _optional(segment.at, ea)
    return idax.BAD_ADDRESS if value is None else value.start


def _resolved_name(value):
    result = _optional(name.resolve, value)
    return idax.BAD_ADDRESS if result is None else result


class _Block:
    def __init__(self, value, index, owner):
        self.id = index
        self.start_ea, self.end_ea = value.start, value.end
        self._value, self._owner = value, owner

    def succs(self):
        return [self._owner[index] for index in self._value.successors]

    def preds(self):
        return [self._owner[index] for index in self._value.predecessors]


def _flow(value):
    result = []
    for index, block in enumerate(graph.flowchart(value.start_ea)):
        result.append(_Block(block, index, result))
    return result


def _decode(ea):
    value = instruction.decode(ea)
    operands = []
    for operand in value.operands:
        operands.append(SimpleNamespace(
            type=operand.type.value, value=operand.value, addr=operand.target_address,
            reg=operand.register_id, offb=operand.encoded_value_byte_offset or 0))
    while len(operands) < 8:
        operands.append(SimpleNamespace(type=0, value=0, addr=0, reg=0, offb=0))
    return value.size, SimpleNamespace(ea=ea, ip=ea, size=value.size, ops=operands)


def _operand_value(ea, index):
    _, value = _decode(ea)
    operand = value.ops[index]
    if operand.type == 0:
        return -1
    if operand.type in (1, 3):
        return operand.reg
    if operand.type == 5:
        return operand.value
    return operand.addr if operand.type in (2, 4, 6, 7) else -1


def _refs_from(ea, flow=False):
    from idax import xref
    return [value.to_address for value in xref.refs_from(ea)
            if value.is_code and (flow or value.type != xref.ReferenceType.FLOW)]


def _refs_to(ea, flow=False):
    from idax import xref
    return [value.from_address for value in xref.refs_to(ea)
            if value.is_code and (flow or value.type != xref.ReferenceType.FLOW)]


def _data_from(ea):
    from idax import xref
    return [value.to_address for value in xref.refs_from(ea) if not value.is_code]


def _data_to(ea):
    from idax import xref
    return [value.from_address for value in xref.refs_to(ea) if not value.is_code]


def _demangle(value, _flags=0):
    return _optional(name.demangled, value) or None


def _string(ea):
    if not address.is_mapped(ea):
        return None
    result = _optional(data.read_string, ea, 0, -1, 0)
    return result.encode("utf-8", "surrogateescape") if result is not None else None


def _forced(ea, index):
    return _optional(instruction.get_forced_operand, ea, index) or ""


def _switch_info(ea):
    value = _optional(graph.switch_table, ea)
    if value is None:
        return None
    return SimpleNamespace(get_jtable_size=lambda: value.entry_count)


def _switch_cases(ea, _info):
    result = graph.switch_cases(ea)
    return SimpleNamespace(cases=[value.values for value in result],
                           targets=[value.target for value in result])


def _literal_assignments(root, relative):
    """Read literal upstream constants without running imports/host setup."""
    root = verify_upstream(root)
    result = {}
    for node in ast.parse((root / relative).read_text()).body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = value
                elif (isinstance(target, ast.Subscript)
                      and isinstance(target.value, ast.Name)
                      and isinstance(result.get(target.value.id), dict)):
                    result[target.value.id][ast.literal_eval(target.slice)] = value
    return result


def _namespace():
    def native_decode(destination, ea):
        size, value = _decode(ea)
        destination.__dict__.update(value.__dict__)
        return size

    wait = []

    def show_wait(message):
        wait.append(ui.WaitBox(message))

    def hide_wait():
        if wait:
            wait.pop().close()

    return dict(
        __name__="idax_diaphora_host", json=json, re=re, os=os, sys=sys,
        time=time, math=math, decimal=decimal, traceback=traceback, md5=md5,
        sqlite3=sqlite3, config=importlib.import_module("diaphora_config"),
        BADADDR=idax.BAD_ADDRESS, FUNCATTR_FLAGS="flags", FUNC_NORET=1,
        FUNC_LIB=4, FUNC_THUNK=128, INF_SHORT_DN=0,
        o_mem=2, o_imm=5, o_far=6, o_near=7, o_displ=4,
        CodeRefsFrom=_refs_from, CodeRefsTo=_refs_to,
        DataRefsFrom=_data_from, DataRefsTo=_data_to,
        Heads=lambda start, end: list(address.items(start, end)),
        Functions=lambda start=0, end=idax.BAD_ADDRESS: [
            value.start for value in function.all() if start <= value.start < end],
        FlowChart=_flow, get_func=_function,
        get_func_name=lambda ea: _optional(function.name_at, ea) or "",
        guess_type=lambda ea: _idc("guess_type", ea) or None,
        get_func_attr=lambda ea, attr: _idc("get_func_attr", ea, attr),
        get_segm_start=_segment_start,
        get_item_size=address.item_size, get_operand_value=_operand_value,
        get_bytes=lambda ea, size, _use_dbg=False: data.read_bytes(ea, size),
        print_insn_mnem=lambda ea: instruction.decode(ea).mnemonic,
        print_operand=instruction.operand_text, GetDisasm=instruction.text,
        GetCommentEx=lambda ea, repeatable: _optional(comment.get, ea, bool(repeatable)),
        GetInstructionList=instruction.mnemonics, demangle_name=_demangle,
        get_string_at=_string, diaphora_decode=_decode,
        get_switch_info=_switch_info, calc_switch_cases=_switch_cases,
        tag_remove=lines.tag_remove, ida_lines=lines,
        get_idb_path=database.idb_path,
        GetInputFileMD5=lambda: bytes.fromhex(database.input_md5()),
        show_wait_box=show_wait, hide_wait_box=hide_wait,
        replace_wait_box=lambda message: wait[-1].update(message) if wait else None,
        user_cancelled=lambda: bool(wait and wait[-1].cancelled),
        warning=print,
        idc=SimpleNamespace(get_type=lambda ea: _idc("get_type", ea) or None,
                            get_func_cmt=lambda ea, repeatable: _optional(function.comment, ea, bool(repeatable)) or "",
                            get_name_ea_simple=_resolved_name),
        ida_bytes=SimpleNamespace(is_forced_operand=lambda ea, index: bool(_forced(ea, index)),
                                  get_forced_operand=_forced),
        ida_ua=SimpleNamespace(insn_t=SimpleNamespace, decode_insn=native_decode),
        ida_idp=SimpleNamespace(is_call_insn=lambda value: instruction.is_call(value.ea)),
        log=print, debug_refresh=lambda *_args: None,
        log_refresh=lambda *_args: None, msg=lambda *_args: None,
    )


_FEATURE_METHODS = {
    "constant_filter", "is_constant", "get_disasm", "get_function_names",
    "extract_function_callers", "extract_function_constants", "extract_function_switches",
    "extract_function_mdindex", "extract_function_pseudocode_features",
    "extract_function_assembly_features", "get_decoded_instruction",
    "extract_function_topological_information", "extract_line_mnem_disasm",
    "extract_microcode", "process_instruction", "process_basic_block",
    "build_topological_relations", "extract_all_features", "initialize_function_data",
    "run_pre_export_hook", "run_post_export_hook", "should_skip_function",
    "build_props_list", "read_function", "get_plain_microcode_line",
    "get_microcode_bblocks", "get_til_names", "export_til",
    "get_modules_using_lfa", "save_compilation_units",
    "get_last_crash_func", "recalculate_primes", "commit_and_start_transaction",
    "do_export", "export", "export_structures",
    "guess_type",
    "clear_pseudo_fields",
}


def _comment_position(value):
    positions = {"DEFAULT": 0, "PARENTHESIS_OPEN": 65, "ASSEMBLY": 66,
                 "ELSE_LINE": 67, "DO_LINE": 68, "SEMICOLON": 69,
                 "OPEN_BRACE": 70, "CLOSE_BRACE": 71, "PARENTHESIS_CLOSE": 72,
                 "LABEL_COLON": 73, "BLOCK_BEFORE": 74, "BLOCK_AFTER": 75,
                 "TRY_LINE": 76}
    if value.kind.name == "ARGUMENT":
        return value.argument_index + 1
    if value.kind.name == "SWITCH_CASE":
        case = value.switch_case_value
        return 0x40000000 | (0x20000000 if case < 0 else 0) | abs(case)
    return positions[value.kind.name]


def _compilation_namespace(root, namespace):
    """Host unchanged LFA and source-string detection through owned values."""
    module_namespace = dict(__name__="idax_diaphora_codecut_values")
    records = upstream_definitions(root, "codecut/module.py",
                                   {"func_info", "bin_module"}, module_namespace)

    def next_function(ea):
        return next((value.start for value in function.all() if value.start > ea),
                    idax.BAD_ADDRESS)

    def calls_from(ea):
        result = set()
        for chunk in function.chunks(ea):
            for head in address.items(chunk.start, chunk.end):
                for target in _refs_from(head):
                    callee = _function(target)
                    if callee is not None and callee.start_ea == target:
                        result.add(target)
        return result

    lfa_namespace = dict(__name__="idax_diaphora_lfa", math=math,
                         module=SimpleNamespace(**records),
                         basicutils=SimpleNamespace(BADADDR=idax.BAD_ADDRESS,
                             NextFunction=next_function, FuncXrefsFrom=calls_from,
                             CodeRefsTo=_refs_to))
    lfa_namespace.update(_literal_assignments(root, "codecut/lfa.py"))
    lfa_methods = {node.name for node in ast.parse((root / "codecut/lfa.py").read_text()).body
                   if isinstance(node, ast.FunctionDef)}
    lfa = upstream_definitions(root, "codecut/lfa.py", lfa_methods, lfa_namespace)

    class StringValue:
        def __init__(self, value):
            self.ea, self.length, self.text = value.address, value.byte_length, value.text

        def __str__(self):
            return self.text

    def strings(string_types):
        options = data.StringListOptions()
        options.string_types = string_types
        options.minimum_length = 5
        options.only_7bit = True
        options.ignore_instructions = False
        options.display_only_existing_strings = False
        data.configure_string_list(options)
        return [StringValue(value) for value in data.string_literals(True)]

    def source_file(ea):
        value = _optional(lines.source_file_at, ea)
        return None if value is None else value.filename

    source_namespace = dict(__name__="idax_diaphora_source_strings", re=re, os=os,
        Counter=Counter, has_nltk=False, get_strings=strings,
        idc=SimpleNamespace(get_func_name=namespace["get_func_name"]),
        idautils=SimpleNamespace(DataRefsTo=_data_to, Functions=namespace["Functions"],
                                 Heads=namespace["Heads"]),
        ida_funcs=SimpleNamespace(get_func=_function),
        ida_gdl=SimpleNamespace(FlowChart=_flow),
        ida_lines=SimpleNamespace(get_sourcefile=source_file))
    source_namespace.update(_literal_assignments(root, "jkutils/IDAMagicStrings.py"))
    source_methods = {"nltk_preprocess", "get_lang", "add_source_file_to",
        "find_source_files_in_strings", "find_source_files_in_debug_info", "get_source_strings"}
    source = upstream_definitions(root, "jkutils/IDAMagicStrings.py", source_methods,
                                  source_namespace)
    namespace.update(lfa=SimpleNamespace(**lfa), HAS_GET_SOURCE_STRINGS=True,
                     get_source_strings=source["get_source_strings"])


def host_engine(root, output):
    root = verify_upstream(root)
    engine = load_backend(root)
    namespace = _namespace()
    tarjan = importlib.import_module("others.tarjan_sort")
    factor = importlib.import_module("jkutils.factor")
    namespace.update(strongly_connected_components=tarjan.strongly_connected_components,
                     robust_topological_sort=tarjan.robust_topological_sort)
    _compilation_namespace(root, namespace)
    hash_namespace = dict(namespace)
    hash_namespace.update(_literal_assignments(root, "jkutils/graph_hashes.py"))
    native_hash = upstream_definitions(root, "jkutils/graph_hashes.py",
                                       {"CKoretKaramitasHash"}, hash_namespace)
    namespace.update(native_hash)
    methods = upstream_definitions(root, "diaphora_ida.py", _FEATURE_METHODS,
                                   namespace, class_name="CIDABinDiff")

    class HostDiff(engine_class(engine)):
        def __init__(self, path):
            super().__init__(str(path))
            self.names = {value.address: value.name for value in name.all()}
            self.decompiler_available = decompiler.available()
            self.min_ea, self.max_ea = database.address_bounds().start, database.address_bounds().end
            self.microcode_ins_list = list(MICROCODE_INSTRUCTIONS)

        def get_base_address(self):
            return database.image_base()

        def decompile_and_get(self, ea):
            if not self.decompiler_available:
                return False
            result = None
            with decompiler.decompile(ea) as value:
                primes = factor.primesbelow(4096)

                class Visitor(decompiler.CtreeVisitor):
                    def __init__(self):
                        super().__init__()
                        self.product = 1

                    def visit_expression(self, item):
                        self.product *= primes[item.type.value]
                        return decompiler.VisitAction.CONTINUE

                    def visit_statement(self, item):
                        self.product *= primes[item.type.value]
                        return decompiler.VisitAction.CONTINUE

                visitor = Visitor()
                value.visit(visitor)
                self.pseudo_hash[ea] = visitor.product
                for entry in value.comments():
                    self.pseudo_comments[entry.address - self.get_base_address()] = [
                        entry.text, _comment_position(entry.position)]
                source_lines = [line for line in value.lines() if not line.startswith("//")]
                if source_lines:
                    result = source_lines[0]
                    self.pseudo[ea] = source_lines[1:]
            self.get_microcode(_function(ea), ea)
            return result

        def get_microcode(self, _function_value, ea):
            if not self.decompiler_available or not self.export_microcode:
                return [], []
            options = decompiler.MicrocodeGenerationOptions()
            options.maturity = decompiler.MicrocodeMaturity.GENERATED
            options.prepare_argument_locations = self.use_decompiler
            value = decompiler.generate_microcode(ea, options)
            self.microcode[ea] = []
            for text in value.text.splitlines():
                line = lines.tag_remove(text).split(";", 1)[0]
                if len(list(filter(None, re.split(r"\W+", line)))) > 2:
                    self.microcode[ea].append(line.strip(" "))

            class Block:
                def __init__(self, block):
                    self.start, self.end = block.start_address, block.end_address
                    self.type = int(block.kind.value == decompiler.MicrocodeBlockKind.EXIT.value)
                    self.succset = block.successors
                    self._text = block.text

                def _print(self, printer):
                    printer.s = self._text

            blocks = [Block(block) for block in value.blocks]
            snapshot = SimpleNamespace(qty=len(blocks), build_graph=lambda: None,
                                       get_mblock=lambda index: blocks[index])
            return self.get_microcode_bblocks(snapshot)

        def GetOrdinalCount(self):
            return types.local_type_count()

        def GetLocalType(self, ordinal, flags):
            return _optional(types.local_type_declaration, ordinal) or ""

        def save_callgraph(self, primes, all_primes, digest):
            processor = database.processor_module_name()
            if idax.BAD_ADDRESS == 0xFFFFFFFFFFFFFFFF:
                processor += "64"
            cursor = self.db_cursor()
            try:
                cursor.execute("insert into program (callgraph_primes, callgraph_all_primes, processor, md5sum) values (?, ?, ?, ?)",
                               (primes, all_primes, processor, digest))
            finally:
                cursor.close()

    for method_name, body in methods.items():
        setattr(HostDiff, method_name, body)

    def monitored_export(self, crashed_before=False):
        self._resuming_export = crashed_before
        self._export_completed = False
        self._export_failure = None
        try:
            methods["do_export"](self, crashed_before)
        except BaseException as failure:
            self._export_failure = failure
            raise
        self._export_completed = True

    HostDiff.do_export = monitored_export
    def checkpoint_rva(self):
        absolute = methods["get_last_crash_func"](self)
        return None if absolute is None else absolute - self.get_base_address()

    HostDiff.get_last_crash_func = checkpoint_rva
    def save_complete_compilation_units(self):
        if getattr(self, "_resuming_export", False):
            # The checkpoint rows outlive upstream's transient function cache.
            self._funcs_cache = {
                int(row["address"]): [row["id"], row["primes_value"], row["pseudocode_primes"]]
                for row in self.db.execute("SELECT id,address,primes_value,pseudocode_primes FROM functions ORDER BY id")}
        methods["save_compilation_units"](self)

    HostDiff.save_compilation_units = save_complete_compilation_units
    def clear_with_pending_comments(self):
        self._pending_pseudo_comments = dict(self.pseudo_comments)
        methods["clear_pseudo_fields"](self)

    def save_with_pending_comments(self, properties):
        current = self.pseudo_comments
        self.pseudo_comments = getattr(self, "_pending_pseudo_comments", current)
        try:
            return super(HostDiff, self).save_function(properties)
        finally:
            self.pseudo_comments = current
            self._pending_pseudo_comments = {}

    HostDiff.clear_pseudo_fields = clear_with_pending_comments
    HostDiff.save_function = save_with_pending_comments
    namespace["hr"] = SimpleNamespace(BLT_STOP=1,
                                        qstring_printer_t=lambda *_args: SimpleNamespace(s=""))
    namespace.update(PRTYPE_MULTI=1, PRTYPE_TYPE=2, PRTYPE_PRAGMA=4, PRTYPE_SEMI=8)
    namespace["idc"].get_numbered_type_name = lambda ordinal: _optional(types.local_type_name, ordinal)
    return HostDiff(output), namespace


def export_current_database(root, output, *, use_decompiler=True, microcode=True,
                            include_library_thunks=False, include_auto_names=True,
                            project_script=None, resume=False):
    """Export the open database in native format; failures retain resumable work.

    A new export rejects an existing destination. Resume requires both the
    partial destination and its crash marker. Upstream commits checkpoints;
    any failed/cancelled operation raises and retains the marker, even when
    the audited export body catches its internal exception.
    """
    output = Path(output).resolve()
    crash = Path(str(output) + "-crash")
    if resume:
        if not output.is_file() or not crash.is_file():
            raise ValueError("Resume requires a partial export and its crash marker")
    elif output.exists() or crash.exists():
        raise FileExistsError(output)
    project_script = str(Path(project_script).resolve(strict=True)) if project_script else None
    database.address_bounds()  # Validate the active host before creating output.
    output.parent.mkdir(parents=True, exist_ok=True)
    value, _ = host_engine(root, output)
    value.use_decompiler = use_decompiler
    value.export_microcode = microcode
    value.exclude_library_thunk = not include_library_thunks
    value.ida_subs = include_auto_names
    value.project_script = project_script
    try:
        value.export()
        if getattr(value, "_export_failure", None) is not None:
            raise RuntimeError("Diaphora export failed; partial export retained") from value._export_failure
        if not getattr(value, "_export_completed", False):
            raise RuntimeError("Diaphora export did not complete")
        with sqlite3.connect(f"{output.as_uri()}?mode=ro", uri=True) as db:
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Exported database failed SQLite integrity validation")
            if db.execute("SELECT COUNT(*) FROM program").fetchone()[0] != 1:
                raise RuntimeError("Export is missing its native program record")
            return {"functions": db.execute("SELECT COUNT(*) FROM functions").fetchone()[0],
                    "compilation_units": db.execute("SELECT COUNT(*) FROM compilation_units").fetchone()[0]}
    except BaseException:
        crash.touch(exist_ok=True)
        raise
    finally:
        value.db_close()

# SDK 940 opcode name facts; compare with the runtime inventory in validation.
MICROCODE_INSTRUCTIONS = ('add', 'and', 'bnot', 'call', 'cfadd', 'cfshl', 'cfshr', 'ext', 'f2f', 'f2i', 'f2u', 'fadd', 'fdiv', 'fmul', 'fneg', 'fsub', 'goto', 'high', 'i2f', 'icall', 'ijmp', 'ja', 'jae', 'jb', 'jbe', 'jcnd', 'jg', 'jge', 'jl', 'jle', 'jnz', 'jtbl', 'jz', 'ldc', 'ldx', 'lnot', 'low', 'mov', 'mul', 'neg', 'nop', 'ofadd', 'or', 'pop', 'push', 'ret', 'sar', 'sdiv', 'seta', 'setae', 'setb', 'setbe', 'setg', 'setge', 'setl', 'setle', 'setnz', 'seto', 'setp', 'sets', 'setz', 'shl', 'shr', 'smod', 'stx', 'sub', 'u2f', 'udiv', 'umod', 'und', 'xds', 'xdu', 'xor')

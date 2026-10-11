"""All-table comparison against audited native feature/export bodies.

Import main(upstream, fixture) in an initialized-capable Python host. Native SDK
imports are confined to this independent reference, never the production host.
"""
from collections import Counter
import decimal
from hashlib import md5
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import traceback

from idax import database
from examples.diaphora.backend import engine_class, load_backend, upstream_definitions
from examples.diaphora.host import export_current_database, _FEATURE_METHODS, _literal_assignments


def native_engine(root, output):
    import idc, idaapi, idautils, ida_hexrays, ida_bytes, ida_lines, ida_funcs, ida_gdl

    namespace = {}
    for module in (idc, idaapi, idautils, ida_hexrays):
        namespace.update(vars(module))
    namespace.update(__name__="native_diaphora_reference", sqlite3=sqlite3,
        idc=idc, idaapi=idaapi, hr=ida_hexrays, ida_bytes=ida_bytes, ida_lines=ida_lines,
        HAS_HEXRAYS=True, json=json, time=time, traceback=traceback, decimal=decimal,
        os=os, re=re, sys=sys, md5=md5, config=importlib.import_module("diaphora_config"),
        primesbelow=importlib.import_module("jkutils.factor").primesbelow,
        strongly_connected_components=importlib.import_module("others.tarjan_sort").strongly_connected_components,
        robust_topological_sort=importlib.import_module("others.tarjan_sort").robust_topological_sort,
        CKoretKaramitasHash=importlib.import_module("jkutils.graph_hashes").CKoretKaramitasHash,
        log=print, debug_refresh=lambda *_: None, CAstVisitorInherits=ida_hexrays.ctree_visitor_t)
    upstream_definitions(root, "diaphora_ida.py",
                         {"CAstVisitor", "CPrinter_t", "diaphora_decode", "get_string_at"}, namespace)
    sys.path.insert(0, str(root / "codecut"))
    namespace["lfa"] = importlib.import_module("codecut.lfa")
    source_namespace = dict(idc=idc, idautils=idautils, ida_funcs=ida_funcs, ida_gdl=ida_gdl,
        ida_lines=ida_lines, re=re, os=os, Counter=Counter, has_nltk=False)
    source_namespace.update(_literal_assignments(root, "jkutils/IDAMagicStrings.py"))
    source = upstream_definitions(root, "jkutils/IDAMagicStrings.py",
        {"get_strings", "nltk_preprocess", "get_lang", "add_source_file_to",
         "find_source_files_in_strings", "find_source_files_in_debug_info", "get_source_strings"},
        source_namespace)
    namespace.update(get_source_strings=source["get_source_strings"],
                     HAS_GET_SOURCE_STRINGS=True, log_refresh=print, msg=print)
    methods = upstream_definitions(root, "diaphora_ida.py", _FEATURE_METHODS | {
        "do_decompile", "decompile_and_get", "get_microcode", "get_microcode_instructions",
        "get_base_address", "GetOrdinalCount", "GetLocalType", "save_callgraph"},
        namespace, class_name="CIDABinDiff")

    class Reference(engine_class(load_backend(root))):
        pass

    for key, value in methods.items():
        setattr(Reference, key, value)
    reference = Reference(str(output))
    reference.names = dict(idautils.Names())
    reference.decompiler_available = True
    reference.microcode_ins_list = reference.get_microcode_instructions()
    reference.min_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    reference.max_ea = idc.get_inf_attr(idc.INF_MAX_EA)
    return reference


def compare_tables(first, second, *, positive_units):
    with sqlite3.connect(first) as one, sqlite3.connect(second) as two:
        tables = [row[0] for row in one.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        assert tables == [row[0] for row in two.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        counts = {}
        for table in tables:
            columns = [row[1] for row in one.execute(f'PRAGMA table_info("{table}")')
                       if row[1] != "export_time"]
            query = "SELECT " + ",".join('"'+name+'"' for name in columns) + ' FROM "'+table+'"'
            actual, expected = one.execute(query).fetchall(), two.execute(query).fetchall()
            if actual != expected:
                differences = []
                for left, right in zip(actual, expected):
                    if left != right:
                        differences = [(columns[index], repr(x)[:160], repr(y)[:160])
                            for index, (x, y) in enumerate(zip(left, right)) if x != y]
                        break
                raise AssertionError((table, len(actual), len(expected), differences))
            counts[table] = len(actual)
        assert counts["functions"] > 0 and counts["instructions"] > 0
        assert counts["program_data"] > 0
        if positive_units:
            assert counts["compilation_units"] > 0 and counts["compilation_unit_functions"] > 0
        return counts


def main(upstream, fixture, *, base_zero=False, modes=((True, True),)):
    root = Path(upstream).resolve()
    load_backend(root)
    database.init()
    with tempfile.TemporaryDirectory(prefix="idax-full-export-") as temporary:
        work = Path(temporary)
        for index, (use_decompiler, microcode) in enumerate(modes):
            outputs = []
            for label in ("native", "idax"):
                binary = work / f"{label}-{index}"
                shutil.copyfile(fixture, binary)
                output = work / f"{label}-{index}.sqlite"
                with database.opened(binary, save_on_exit=False):
                    if base_zero:
                        import ida_segment, idaapi
                        # Exercise an additional address-base variant.
                        assert ida_segment.rebase_program(-idaapi.get_imagebase(), ida_segment.MSF_FIXONCE) == 0
                    if label == "native":
                        value = native_engine(root, output)
                        value.use_decompiler = use_decompiler
                        value.export_microcode = microcode
                        value.exclude_library_thunk = False
                        value.ida_subs = True
                        try:
                            value.export()
                        finally:
                            value.db_close()
                    else:
                        export_current_database(root, output, use_decompiler=use_decompiler,
                                                microcode=microcode, include_library_thunks=True)
                outputs.append(output)
            counts = compare_tables(*outputs, positive_units=True)
            print("ALL_TABLES_EQUAL", {"decompiler": use_decompiler,
                "microcode": microcode, "base_zero": base_zero, "counts": counts})

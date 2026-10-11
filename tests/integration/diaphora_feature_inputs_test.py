"""Independent IDAPython/native comparison for copied Diaphora feature inputs.

Pass a fresh owned x86-64 build of decompiler_semantic_metadata_host.cpp.
Run main from an imported module: IDAPython initialization owns __main__.
"""
from idax import database, function, instruction, graph, decompiler, BAD_ADDRESS
from idax import NotFoundError

def main(fixture):
    database.init()
    with database.opened(str(fixture), save_on_exit=False):
        import idautils, ida_nalt, ida_xref, ida_hexrays, ida_funcs
        names = instruction.mnemonics()
        expected = idautils.GetInstructionList()
        assert names == expected, (len(names),len(expected))
        print("active_mnemonics:",len(names),"native_order_equal=True")
        switches = 0
        for fn in function.all():
            if "idax_metadata_switch" not in fn.name: continue
            for ea in idautils.FuncItems(fn.start):
                si = ida_nalt.get_switch_info(ea)
                if si is None: continue
                native = ida_xref.calc_switch_cases(ea, si)
                cases = graph.switch_cases(ea)
                got = [(list(c.values),c.target) for c in cases]
                wanted = [(list(v),int(t)) for v,t in zip(native.cases,native.targets)]
                assert got == wanted, (got,wanted)
                assert any(v < 0 for group,_ in got for v in group)
                assert {v for group,_ in got for v in group} == set(range(-3,13))
                switches += 1
                print("switch: groups=",len(got),"signed_values_equal=True")
            options = decompiler.MicrocodeGenerationOptions()
            options.maturity = decompiler.MicrocodeMaturity.GENERATED
            owned = decompiler.generate_microcode(fn.start,options)
            native = ida_hexrays.gen_microcode(ida_hexrays.mba_ranges_t(ida_funcs.get_func(fn.start)),ida_hexrays.hexrays_failure_t(),ida_hexrays.mlist_t(),ida_hexrays.DECOMP_WARNINGS,ida_hexrays.MMAT_GENERATED)
            assert native is not None
            native.build_graph()
            printer = ida_hexrays.qstring_printer_t(None,True)
            native._print(printer)
            assert owned.text == printer.s, (owned.text[:150],printer.s[:150])
            for block in owned.blocks:
                printer = ida_hexrays.qstring_printer_t(None,True)
                native.get_mblock(block.index)._print(printer)
                assert block.text == printer.s, block.index
            retained_text = [block.text for block in owned.blocks]
            print("microcode: blocks=",len(owned.blocks),"native_formatted_text_equal=True")
        assert switches > 0
        try:
            graph.switch_cases(BAD_ADDRESS)
            raise AssertionError("missing switch accepted")
        except NotFoundError:
            pass
    assert names
    assert owned.text
    assert [block.text for block in owned.blocks] == retained_text
    print("copied_values_survive_database_close=True")

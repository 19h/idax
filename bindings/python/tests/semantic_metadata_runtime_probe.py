"""Fresh-process evidence for owned graph fields, child ancestry, and dyld parsing."""
from __future__ import annotations
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from idax import IdaxError, analysis, database, decompiler as dc, dyld_cache, function, instruction, plugin

class Visitor(dc.CtreeVisitor):
    def __init__(self):
        super().__init__()
        self.children = []
        self.parents = []
    def child(self, child, parent):
        ancestors = child.parents()
        direct = child.parent()
        assert ancestors and direct is not None
        assert direct.type == parent.type and direct.address == parent.address
        self.children.append(child)
        self.parents.extend(ancestors)
    def visit_expression(self, expression):
        for accessor in (expression.left, expression.right, expression.third):
            try:
                child = accessor()
            except IdaxError:
                continue
            self.child(child, expression)
        return dc.VisitAction.CONTINUE
    def visit_statement(self, statement):
        for accessor in (statement.condition, statement.init_expression, statement.step_expression,
                         statement.expression, statement.then_branch, statement.else_branch, statement.body):
            try:
                child = accessor()
            except IdaxError:
                continue
            self.child(child, statement)
        if statement.type == dc.ItemType.STMT_BLOCK:
            for index in range(statement.block_size()):
                self.child(statement.block_statement(index), statement)
        return dc.VisitAction.CONTINUE

def main():
    if len(sys.argv) != 2:
        raise SystemExit('expected semantic fixture path')
    counts = dict(floats=0, stacks=0, calls=0, switches=0)
    def operand(value, blocks):
        if value.floating_point_constant == 65536.0:
            counts['floats'] += 1
        if value.kind == dc.MicrocodeOperandKind.CALL_ARGUMENTS:
            counts['calls'] += 1
            assert len(value.call_argument_properties) == len(value.call_arguments)
            assert all(register.byte_width > 0 for register in value.call_return_registers)
        if value.kind == dc.MicrocodeOperandKind.SWITCH_CASES:
            counts['switches'] += 1
        assert all(case.target_block in blocks for case in value.switch_cases)
        assert value.switch_default_target is None or value.switch_default_target in blocks
        if value.nested_instruction is not None:
            micro_instruction(value.nested_instruction, blocks)
        if value.referenced_operand is not None:
            operand(value.referenced_operand, blocks)
        for argument in [*value.call_arguments, *value.call_return_operands]:
            operand(argument, blocks)
    def micro_instruction(value, blocks):
        for item in (value.left, value.right, value.destination):
            operand(item, blocks)
    def graph(model):
        assert model.stack_frame_size >= 0 and model.local_stack_size >= 0 and model.saved_register_size >= 0
        assert model.return_variable_index is None or model.return_variable_index < len(model.local_variables)
        blocks = {block.index for block in model.blocks}
        for block in model.blocks:
            for value in block.instructions:
                micro_instruction(value, blocks)
        for variable in model.local_variables:
            assert isinstance(variable.has_nice_name, bool)
            if variable.storage == dc.VariableStorage.STACK:
                counts['stacks'] += 1
                assert variable.stack_offset >= 0 and variable.location is not None
                assert variable.location.stack_offset == variable.stack_offset
    with tempfile.TemporaryDirectory(prefix='idax-python-metadata-') as directory:
        directory = Path(directory)
        fixture = directory / 'metadata_fixture'
        shutil.copy2(sys.argv[1], fixture)
        cache = directory / 'cache_fixture'
        data = bytearray(0x300)
        data[:15] = b'dyld_v1  arm64e'
        struct.pack_into('<I', data, 0x10, 0x1c8)
        struct.pack_into('<II', data, 0x1c0, 0x200, 1)
        struct.pack_into('<Q', data, 0x200, 0xfedcba9876543210)
        struct.pack_into('<I', data, 0x218, 0x240)
        data[0x240:0x240+20] = b'/usr/lib/owned.dylib'
        cache.write_bytes(data)
        modules = dyld_cache.list_modules(cache)
        assert len(modules) == 1 and modules[0].path == '/usr/lib/owned.dylib'
        assert modules[0].load_address == 0xfedcba9876543210
        struct.pack_into('<I', data, 0x1c4, 2)
        cache.write_bytes(data)
        try:
            dyld_cache.list_modules(cache)
        except IdaxError:
            pass
        else:
            raise AssertionError('partial cache inventory was accepted')
        runtime_options = database.RuntimeOptions(quiet=True, plugin_policy=database.PluginLoadPolicy(disable_user_plugins=True))
        database.init(['idax-python-metadata'], runtime_options)
        database.open(fixture, database.OpenMode.ANALYZE)
        retained, visitors = [], []
        try:
            analysis.wait()
            assert not dyld_cache.is_available()
            assert not plugin.is_plugin_available('')
            assert dc.available(), 'decompiler required for this evidence'
            for fn in function.all():
                if 'idax_metadata_' not in fn.name:
                    continue
                assert instruction.decode(fn.start).branch_condition == instruction.branch_condition(fn.start)
                for maturity in [dc.MicrocodeMaturity.GENERATED, dc.MicrocodeMaturity.PREOPTIMIZED,
                                 dc.MicrocodeMaturity.LOCALLY_OPTIMIZED, dc.MicrocodeMaturity.CALLS_ANALYZED,
                                 dc.MicrocodeMaturity.GLOBALLY_OPTIMIZED1, dc.MicrocodeMaturity.GLOBALLY_OPTIMIZED2,
                                 dc.MicrocodeMaturity.GLOBALLY_OPTIMIZED3, dc.MicrocodeMaturity.LOCAL_VARIABLES]:
                    options = dc.MicrocodeGenerationOptions()
                    options.maturity = maturity
                    model = dc.generate_microcode(fn.start, options)
                    graph(model)
                    retained.append(model)
                with dc.decompile(fn.start) as decompiled:
                    visitor = Visitor()
                    options = dc.VisitOptions()
                    options.track_parents = True
                    decompiled.visit(visitor, options)
                    visitors.append(visitor)
            assert all(counts.values())
            assert sum(len(visitor.children) for visitor in visitors) > 0
            for visitor in visitors:
                for child in visitor.children:
                    try:
                        child.type
                    except IdaxError:
                        pass
                    else:
                        raise AssertionError('callback child remained valid after callback return')
                for parent in visitor.parents:
                    assert isinstance(parent.address, int)
            for model in retained:
                graph(model)
            saved = directory / 'saved.i64'
            database.save_to(saved)
            assert saved.exists()
            database.close(False)
            database.open(saved, database.OpenMode.SKIP_ANALYSIS)
        finally:
            database.close(False)
    print(f'semantic metadata passed: {counts}')

if __name__ == '__main__':
    main()

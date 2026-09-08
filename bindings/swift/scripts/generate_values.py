#!/usr/bin/env python3
"""Generate repetitive Swift value transport from an explicit semantic schema.

The canonical C++ headers define concepts and enums. The shared C header only
provides private transport. Unsupported operations are reported for hand-written
adapters; generation never substitutes a stub or drops an output field.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SWIFT = ROOT / 'bindings/swift'
SCHEMA = json.loads((SWIFT / 'value_schema.json').read_text())
HEADER = ROOT / 'bindings/rust/idax-sys/shim/idax_shim.h'
KEYWORDS = set('class struct enum protocol extension func var let in out default switch case repeat continue break return throw throws try catch do defer if else for while where associatedtype typealias static public internal private fileprivate open operator subscript init deinit import self Type Any true false as is'.split())

def clean(text):
    return re.sub(r'//[^\n]*|/\*.*?\*/', '', text, flags=re.S)

def camel(name):
    parts = name.split('_')
    first = parts[0]
    if first.isupper(): first = first.lower()
    else: first = first[:1].lower() + first[1:]
    return first + ''.join(x[:1].upper() + x[1:] for x in parts[1:])

def ident(name):
    result = camel(name)
    return f'`{result}`' if result in KEYWORDS else result

def ctype(text):
    return re.sub(r'\s+', ' ', re.sub(r'\s*\*\s*', '*', text.strip())).replace('struct ', '')

def declaration(text):
    found = re.fullmatch(r'(.+?)([A-Za-z_]\w*)', text.strip())
    if not found: raise ValueError(text)
    return ctype(found[1]), found[2]

PRIMITIVES = {'int':'Int32','unsigned int':'UInt32','int8_t':'Int8','uint8_t':'UInt8', 'int16_t':'Int16','uint16_t':'UInt16','int32_t':'Int32','uint32_t':'UInt32','int64_t':'Int64','uint64_t':'UInt64','size_t':'Int','double':'Double','float':'Float'}
source = clean(HEADER.read_text())
structs = {name:[declaration(f) for f in body.split(';') if f.strip()] for name,body in re.findall(r'typedef struct (\w+)\s*\{(.*?)\}\s*\w+\s*;',source,re.S)}
functions = []
for ret,name,args in re.findall(r'^([\w *]+?)\s+(idax_\w+)\s*\((.*?)\);',source,re.M|re.S):
    if '\n' in ret.strip(): continue
    functions.append((ctype(ret),name,[] if args.strip()=='void' else [declaration(x) for x in args.split(',')]))

records = SCHEMA['records']
field_types = SCHEMA.get('field_types',{})
param_types = SCHEMA.get('parameter_types',{})
return_types = SCHEMA.get('return_types',{})
free_functions = SCHEMA['free_functions']

# Misspelled schema keys must not silently leave native fields unrefined.
function_arguments = {name: {argument for _, argument in arguments} for _, name, arguments in functions}
record_fields = {name: {field for _, field in fields} for name, fields in structs.items()}
for table in ['field_types', 'field_defaults', 'optional_fields', 'sentinel_fields',
              'arrays', 'parameter_types', 'parameter_defaults']:
    known = function_arguments if table.startswith('parameter_') else record_fields
    for key in SCHEMA.get(table, {}):
        owner, field = key.rsplit('.', 1)
        if field not in known.get(owner, set()):
            raise SystemExit(f'Unknown native schema key in {table}: {key}')
for key in SCHEMA.get('nullable_strings', []):
    owner, field = key.rsplit('.', 1)
    if field not in record_fields.get(owner, set()):
        raise SystemExit('Unknown nullable native string field: ' + key)

# Both fields and function arguments carry explicit enum/boolean refinements.
def semantic_type(owner,name,ct):
    return field_types.get(owner+'.'+name, param_types.get(owner+'.'+name, PRIMITIVES.get(ct)))

def decode(expr,ct,st,operation):
    if st == 'Bool': return expr+' != 0'
    if st not in PRIMITIVES.values() and ct in PRIMITIVES: return f'try checkedNativeEnum({st}.self, {expr}, {operation})'
    return expr

def enum_source(domain):
    text=clean((ROOT / f'include/ida/{domain}.hpp').read_text())
    result=[]
    for name,body in re.findall(r'^enum class (\w+)(?:\s*:\s*[^\{]+)?\s*\{(.*?)\};',text,re.M|re.S):
        if name in SCHEMA.get('skip_enums',{}).get(domain,[]):continue
        value=-1;cases=[];values={}
        for entry in body.split(','):
            entry=entry.strip()
            if not entry:continue
            pieces=entry.split('=',1);item=pieces[0].strip()
            if len(pieces)>1:
                expr=pieces[1].strip().replace("'",'')
                expr=re.sub(r'(?<=[0-9a-fA-F])[uUlL]+\b','',expr)
                if not re.fullmatch(r'[\dxa-fA-F\s<>()|+\-]+',expr):raise ValueError(f'Unsupported enum expression {domain} {name}: {expr}')
                value=int(eval(expr,{'__builtins__':{}},{}))
            else:value+=1
            if value in values:
                cases.append(f'        public static let {ident(item)} = Self.{values[value]}')
            else:
                values[value]=ident(item)
                cases.append(f'        case {ident(item)} = {value}')
        result.append(f'    public enum {SCHEMA.get("enum_names",{}).get(domain+"."+name,name)}: Int32, CaseIterable, Sendable {{\n'+ '\n'.join(cases)+'\n    }\n')
    return result

record_output={}
pending=[]
for cname,st in records.items():
    if cname in SCHEMA.get('manual_records',[]):continue
    try:
        fields=structs[cname];props=[];params=[];assigns=[];copies=[]
        count_fields={}
        optional_fields=SCHEMA.get('optional_fields', {})
        presence_fields={flag for key,flag in optional_fields.items() if key.startswith(cname+'.')}
        for ct,name in fields:
            key=cname+'.'+name
            if key in SCHEMA.get('arrays',{}):count_fields[SCHEMA['arrays'][key]]=name
        for ct,name in fields:
            if name in count_fields or name in presence_fields:continue
            key=cname+'.'+name
            sn=ident(name);typ=semantic_type(cname,name,ct)
            native='native.'+name
            if key in SCHEMA.get('arrays',{}):
                count=SCHEMA['arrays'][key];element=ct.rstrip('*');et=records.get(element,PRIMITIVES.get(element))
                if et is None:raise ValueError('unmapped array '+key)
                typ='['+et+']'
                expr=f'try copyNativeValues({native}, count: Int(native.{count}), operation) {{ (value) throws(IDAError) -> {et} in '
                expr+=f'try {et}(copying: value, operation)' if element in records else 'value'
                expr+=' }'
            elif ct=='char*':
                typ='String';expr=f'try borrowCString({native}.map {{ UnsafePointer($0) }}, operation)'
                if key in SCHEMA.get('nullable_strings',[]):
                    typ+='?';expr=f'{native} == nil ? nil : ({expr})'
            elif ct.endswith('*') and ct[:-1] in records:
                typ=records[ct[:-1]]+'?'
                expr=f'try copyNativeOptional({native}, operation) {{ (value) throws(IDAError) -> {records[ct[:-1]]} in try {records[ct[:-1]]}(copying: value, operation) }}'
            elif ct in records:typ=records[ct];expr=f'try {typ}(copying: {native}, operation)'
            elif typ is not None:expr=decode(native,ct,typ,'operation')
            else:raise ValueError('unmapped field '+key+' '+ct)
            if key in optional_fields:
                typ+='?'
                expr=f'native.{optional_fields[key]} != 0 ? ({expr}) : nil'
            if key in SCHEMA.get('sentinel_fields',{}):
                rule=SCHEMA['sentinel_fields'][key]
                typ=rule['type']+'?'
                expr=f'{native} == {rule["sentinel"]} ? nil : {rule["type"]}({native})'
            props.append(f'        public var {sn}: {typ}')
            default=SCHEMA.get('field_defaults',{}).get(key)
            params.append(f'{sn}: {typ}'+(' = '+default if default is not None else ''))
            assigns.append(f'            self.{sn} = {sn}')
            copies.append(f'            self.{sn} = {expr}')
        leaf=st.split('.')[-1]
        if cname in SCHEMA.get('recursive_records',[]):
            inner='\n'.join(p.replace('public var','var') for p in props)
            computed=[]
            names=[]
            for p in props:
                name,typ=p.strip().removeprefix('public var ').split(': ',1);names.append(name)
                computed.append(f'        public var {name}: {typ} {{\n            get {{ fields.{name} }}\n            set {{ var value = fields; value.{name} = newValue; storage = .value(value) }}\n        }}')
            initvalues=', '.join(n+': '+n for n in names)
            nativevalues=',\n                '.join(x.strip().removeprefix('self.').replace(' = ',': ',1) for x in copies)
            code=f'    public struct {leaf}: Equatable, Sendable {{\n        private struct Fields: Equatable, Sendable {{\n{inner}\n        }}\n        private indirect enum Storage: Equatable, Sendable {{ case value(Fields) }}\n        private var storage: Storage\n        private var fields: Fields {{ switch storage {{ case .value(let value): return value }} }}\n'+ '\n'.join(computed)+f'\n        public init({", ".join(params)}) {{ storage = .value(Fields({initvalues})) }}\n        internal init(copying native: {cname}, _ operation: String) throws(IDAError) {{\n            storage = .value(Fields(\n                {nativevalues}))\n        }}\n    }}\n'
        else:
            code=f'    public struct {leaf}: Equatable, Sendable {{\n'+ '\n'.join(props)+f'\n\n        public init({", ".join(params)}) {{\n'+ '\n'.join(assigns)+f'\n        }}\n\n        internal init(copying native: {cname}, _ operation: String) throws(IDAError) {{\n'+ '\n'.join(copies)+'\n        }\n    }\n'
        record_output[cname]=(st.split('.')[0],code)
    except (ValueError,KeyError) as error:pending.append({'record':cname,'reason':str(error)})

outputs={domain:[] for domain in SCHEMA['domains']}
covered=[]
for ret,fn,args in functions:
    domain=fn.split('_')[1]
    if domain not in outputs or fn in SCHEMA.get('manual_functions',[]):continue
    if fn in free_functions.values() or fn.endswith('_free'):continue
    try:
        method=SCHEMA.get('method_names',{}).get(fn,camel(fn[len('idax_'+domain+'_'):]))
        ns=SCHEMA['domains'][domain]
        op=f'"{ns}.{method}"'
        params=[];pre=[];setup=[];cleanup=[];callargs=[];strings=[];out=[];array_count=None;optional=None;owned_types=[]
        input_counts={}
        input_arrays=SCHEMA.get('input_arrays', {})
        for ct,name in args:
            if fn+'.'+name in input_arrays:
                input_counts[input_arrays[fn+'.'+name]]=name
        for ct,name in args:
            if name in input_counts:
                value=input_counts[name]
                callargs.append(f'c_{value}_count' if ct=='size_t' else f'{PRIMITIVES[ct]}(c_{value}_count)')
                continue
            if name=='has_value' and ct=='int*':
                optional=name;setup.append('        var has_value: Int32 = 0');callargs.append('&has_value');continue
            if ct.endswith('*') and not ct.startswith('const ') and (name.startswith('out') or name in SCHEMA.get('output_parameters',{}).get(fn,[])):
                base=ct[:-1]
                if base=='char**':
                    count=next((n for t,n in args if t=='size_t*' and n in ['count','out_count','out_len']),None)
                    if count is None:raise ValueError('string array without count')
                    free=SCHEMA.get('string_array_frees',{}).get(fn)
                    if free is None:raise ValueError('string array without audited free')
                    array_count=count
                    setup.append(f'        var {name}: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?')
                    cleanup.append(f'{free}({name}, {count})')
                    out.append((name,'[String]',f'try copyNativeValues({name}, count: {count}, {op}) {{ (value) throws(IDAError) -> String in try borrowCString(value.map {{ UnsafePointer($0) }}, {op}) }}'))
                elif base=='char*':
                    setup.append(f'        var {name}: UnsafeMutablePointer<CChar>?')
                    cleanup.append(f'idax_free_string({name})')
                    out.append((name,'String',f'try borrowCString({name}.map {{ UnsafePointer($0) }}, {op})'))
                elif base in PRIMITIVES:
                    st=return_types.get(fn,PRIMITIVES[base]);setup.append(f'        var {name}: {PRIMITIVES[base]} = 0')
                    out.append((name,st,decode(name,base,st,op)))
                elif base in records and base in record_output:
                    st=records[base];setup.append(f'        var {name} = {base}()')
                    if base in free_functions:cleanup.append(f'{free_functions[base]}(&{name})')
                    out.append((name,st,f'try {st}(copying: {name}, {op})'))
                elif base.endswith('*') and (base[:-1] in records or base[:-1] in PRIMITIVES):
                    elem=base[:-1];st=records.get(elem,PRIMITIVES.get(elem));native=elem if elem in records else PRIMITIVES[elem]
                    setup.append(f'        var {name}: UnsafeMutablePointer<{native}>?')
                    count=next((n for t,n in args if t=='size_t*' and n in ['count','out_count','out_len']),None)
                    if count is None:raise ValueError('array without count')
                    array_count=count
                    free=free_functions.get(elem+'[]')
                    if free is None:raise ValueError('array without audited free')
                    cleanup.append(f'{free}({name}, {count})' if free in SCHEMA.get('counted_frees',[]) else f'{free}({name})')
                    expr=f'try copyNativeValues({name}, count: {count}, {op}) {{ (value) throws(IDAError) -> {st} in '
                    expr+=f'try {st}(copying: value, {op})' if elem in records else 'value'
                    out.append((name,'['+st+']',expr+' }'))
                else:raise ValueError('unmapped output '+name+' '+ct)
                callargs.append('&'+name)
            elif ct=='size_t*' and name in ['count','out_count','out_len']:
                setup.append(f'        var {name}: Int = 0');callargs.append('&'+name)
            elif fn+'.'+name in input_arrays:
                element=ct.removeprefix('const ').rstrip('*')
                sn=ident(name)
                if ct=='const char*const*':
                    params.append(f'{sn}: [String]')
                    strings.append((f'try checkedCStringArray({sn}, {op}) {{ c_{name}, c_{name}_count in ', '}'))
                elif element in PRIMITIVES:
                    params.append(f'{sn}: [{PRIMITIVES[element]}]')
                    strings.append((f'{sn}.withUnsafeBufferPointer {{ c_{name}_buffer in let c_{name} = c_{name}_buffer.baseAddress; let c_{name}_count = c_{name}_buffer.count; return ', '}'))
                else:raise ValueError('unmapped input array element '+element)
                callargs.append('c_'+name)
            elif ct=='void*' and param_types.get(fn+'.'+name)=='TypeInfo':
                sn=ident(name);params.append(f'{sn}: TypeInfo')
                pre.append(f'        let c_{name} = handles[{len(owned_types)}]')
                owned_types.append(sn)
                callargs.append('c_'+name)
            elif ct=='const char*':
                sn=ident(SCHEMA.get('parameter_names',{}).get(name,name));params.append(f'{sn}: String');pre.append(f'        try validateCString({sn}, {op})');strings.append((f'{sn}.withCString {{ c_{name} in ', '}'));callargs.append('c_'+name)
            elif ct in PRIMITIVES:
                st=semantic_type(fn,name,ct);sn=ident(SCHEMA.get('parameter_names',{}).get(name,name));params.append(f'{sn}: {st}')
                if ct=='size_t':pre.append(f'        try requireNonnegative({sn}, {op})')
                callargs.append(f'({sn} ? 1 : 0)' if st=='Bool' else f'{PRIMITIVES[ct]}({sn}.rawValue)' if st not in PRIMITIVES.values() else sn)
            else:raise ValueError('unmapped input '+name+' '+ct)
        defaults={ident(SCHEMA.get('parameter_names',{}).get(name,name)):SCHEMA['parameter_defaults'][fn+'.'+name]
                  for ct,name in args if fn+'.'+name in SCHEMA.get('parameter_defaults',{})}
        params=[param+(' = '+defaults[param.split(':',1)[0]] if param.split(':',1)[0] in defaults else '') for param in params]
        if array_count:out=[x for x in out if x[0]!=array_count]
        nullable_string=fn in SCHEMA.get('nullable_string_results',[])
        if nullable_string:
            if optional or len(out)!=1 or out[0][1]!='String':
                raise ValueError('nullable string result requires one String output and no presence flag')
            name,typ,expr=out[0]
            out=[(name,'String?',f'{name} == nil ? nil : ({expr})')]
        if ret not in ['int','void']+list(PRIMITIVES):raise ValueError('unmapped direct return '+ret)
        direct=return_types.get(fn) if not out else None
        if not out and direct:rtype=direct
        elif len(out)==1:rtype=out[0][1]+('?' if optional else '')
        elif len(out)>1:rtype='('+', '.join(ident(n)+': '+t for n,t,e in out)+')'
        else:rtype='Void'
        code=[f'    public static func {ident(method)}({", ".join(params)}) throws(IDAError)'+(' -> '+rtype if rtype!='Void' else '')+' {',f'        try requireRuntimeThread({op})']+pre+setup
        if cleanup:code.append('        defer { '+ '; '.join(cleanup)+' }')
        call=f'{fn}({", ".join(callargs)})'
        for prefix,suffix in reversed(strings):call=('try ' if 'try ' in call and not prefix.startswith('try ') else '')+prefix+call+suffix
        if direct:
            code.append('        let result = '+call)
            code.append('        return '+decode('result',ret,direct,op))
        elif ret=='void':code.append('        '+call)
        else:code.append(f'        try checkStatus({call}, {op})')
        if optional:code.append('        guard has_value != 0 else { return nil }')
        if len(out)==1:code.append('        return '+out[0][2])
        elif len(out)>1:code.append('        return ('+', '.join(e for n,t,e in out)+')')
        code.append('    }\n')
        if owned_types:
            code=[code[0],f'        return try TypeInfo.withHandles([{", ".join(owned_types)}], {op}) {{ (handles) throws(IDAError) -> {rtype} in']+['    '+line for line in code[1:-1]]+['        }',code[-1]]
        outputs[domain].append('\n'.join(code));covered.append(fn)
    except ValueError as error:pending.append({'function':fn,'reason':str(error)})

parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
for domain,content in outputs.items():
    ns=SCHEMA['domains'][domain]
    parts=enum_source(domain)+[code for owner,code in record_output.values() if owner==ns]+content
    text='// Generated by scripts/generate_values.py from value_schema.json.\n// Edit the semantic schema or add a hand-written adapter; do not edit this file.\ninternal import CIDAX\n\npublic enum '+ns+' {\n'+ '\n'.join(parts)+'}\n'
    path=SWIFT/'Sources/IDAX'/f'{ns}+Values.swift'
    if args.check:
        if not path.exists() or path.read_text()!=text:raise SystemExit(f'Stale generated Swift: {path.name}')
    else:path.write_text(text)
report={'generated_functions':covered,'pending':pending}
report_text=json.dumps(report,indent=2)+'\n'
report_path=SWIFT/'value_transport_audit.json'
if args.check:
    if report_path.read_text()!=report_text:raise SystemExit('Stale value transport audit')
else:report_path.write_text(report_text)
print(f'{len(covered)} generated functions; {len(pending)} operations/records require explicit adapters')

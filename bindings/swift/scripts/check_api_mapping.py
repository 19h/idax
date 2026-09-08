#!/usr/bin/env python3
"""Validate declaration-level C++ to public Swift mappings.

Each current declaration, overload, field, alias and enum case must have an
explicit record. Targets are checked against the compiler's public symbol graph;
a namespace name alone cannot satisfy a member. The map records language
adaptations separately from callable/field equivalence. Runtime evidence is
maintained independently because a declaration mapping cannot prove behavior.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'bindings/swift'

def cpp_id(entry):
    return hashlib.sha256(json.dumps({k:entry[k] for k in ('name','kind','signature')},sort_keys=True).encode()).hexdigest()[:20]

def cpp_fingerprint(entry):
    """Include defaults, templates, macro bodies and field initializers."""
    return hashlib.sha256(json.dumps(entry,sort_keys=True).encode()).hexdigest()

def normalized(value):
    return re.sub('[^a-z0-9]','',value.split('(',1)[0].lower())

def load_inputs():
    cpp=json.loads((BASE/'cpp_api_inventory.json').read_text())
    swift=json.loads((BASE/'swift_api_inventory.json').read_text())
    return cpp,swift

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    options=parser.parse_args()
    cpp,swift=load_inputs()
    actual={x['id']:x for x in swift['declarations']}
    swift_paths={'.'.join(x['path']):[] for x in actual.values()}
    for entry in actual.values():swift_paths['.'.join(entry['path'])].append(entry['id'])
    expected={cpp_id(x):(d['domain'],x) for d in cpp['domains'] for x in d['declarations']}
    found={};errors=[];counts={}
    for path in sorted((BASE/'api_mapping').glob('*.json')):
        document=json.loads(path.read_text())
        for entry in document['declarations']:
            key=entry['cpp_id']
            if key not in expected:errors.append(f'{path.name}: stale C++ identity {key}');continue
            if key in found:errors.append(f'{path.name}: duplicate C++ identity {key}');continue
            domain,decl=expected[key];found[key]=entry
            if document['domain']!=domain:errors.append(f'{path.name}: wrong domain for {decl["name"]}')
            if entry.get('cpp_name')!=decl['name'] or entry.get('cpp_signature')!=decl['signature']:
                errors.append(f'{path.name}: changed declaration {decl["name"]}')
            if entry.get('cpp_fingerprint')!=cpp_fingerprint(decl):
                errors.append(f'{decl["name"]}: declaration/default/export definition requires semantic review')
            mode=entry.get('mapping')
            if mode not in ['direct','adapted','private_bridge']:
                errors.append(f'{decl["name"]}: unresolved mapping {mode}');continue
            targets=entry.get('swift',[])
            if not targets:errors.append(f'{decl["name"]}: no concrete public Swift target')
            for target in targets:
                if target not in actual:errors.append(f'{decl["name"]}: stale Swift identity {target}')
                elif decl['kind'] in ['field','enum_case','method','function'] and mode=='direct':
                    if actual[target]['kind'] in ['swift.enum','swift.struct','swift.class','swift.protocol']:
                        errors.append(f'{decl["name"]}: type-only target for a direct member')
            resolved=[actual[target] for target in targets if target in actual]
            readable=[{'path':'.'.join(symbol['path']),'declaration':symbol['declaration']} for symbol in resolved]
            if entry.get('swift_targets')!=readable:
                errors.append(f'{decl["name"]}: readable Swift targets require synchronization')
            if mode=='direct' and resolved:
                if decl['kind']=='field' and decl['signature']=='bool':
                    if not any(re.search(r'\bBool\b',symbol['declaration']) for symbol in resolved):
                        errors.append(f'{decl["name"]}: native Boolean field lost its semantic type')
                native_booleans=sum(parameter['type']=='bool' for parameter in decl.get('parameters',[]))
                def boolean_inputs(symbol):
                    return sum(any(fragment.get('spelling')=='Bool' for fragment in parameter.get('declarationFragments',[]))
                               for parameter in symbol.get('functionSignature',{}).get('parameters',[]))
                if native_booleans and max(boolean_inputs(symbol) for symbol in resolved)<native_booleans:
                    errors.append(f'{decl["name"]}: native Boolean inputs require a semantic type or explicit adaptation')
                native_defaults=sum('default' in parameter for parameter in decl.get('parameters',[]))
                if native_defaults and max(symbol['declaration'].count(' = ') for symbol in resolved)<native_defaults:
                    errors.append(f'{decl["name"]}: native defaults require preservation or explicit adaptation')
            if not entry.get('rationale','').strip():errors.append(f'{decl["name"]}: missing semantic rationale')
            counts[mode]=counts.get(mode,0)+1
    for key,(domain,decl) in expected.items():
        if key not in found:errors.append(f'{domain}: unmapped {decl["name"]} [{decl["signature"]}]')
    if errors:
        print('\n'.join(errors));raise SystemExit(f'API mapping failed: {len(errors)} unresolved declarations or targets')
    print(f'API mapping: {len(expected)} C++ declarations in {len(cpp["domains"])} headers; {len(actual)} actual public Swift symbols; '+', '.join(f'{n} {k}' for k,n in sorted(counts.items())))

if __name__=='__main__':main()

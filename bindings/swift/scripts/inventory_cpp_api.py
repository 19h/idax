#!/usr/bin/env python3
"""Inventory public C++ declarations, overloads, enum cases, fields and exports.

Requires a C++23 Clang toolchain and the pinned IDA SDK headers.
The proprietary runtime is not loaded.
This is a declaration inventory, not proof of binding implementation.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
UMBRELLA = ROOT / 'include/ida/idax.hpp'
OUTPUT = ROOT / 'bindings/swift/cpp_api_inventory.json'

def objects(text):
    decoder=json.JSONDecoder();pos=0
    while pos<len(text):
        while pos<len(text) and text[pos].isspace():pos+=1
        if pos==len(text):break
        value,pos=decoder.raw_decode(text,pos);yield value

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    parser.add_argument('--clang',default=os.environ.get('CXX'))
    parser.add_argument('--sdk',default=os.environ.get('IDASDK'))
    options=parser.parse_args()
    compiler=options.clang or (subprocess.check_output(['xcrun','--find','clang++'],text=True).strip() if sys.platform=='darwin' else shutil.which('clang++'))
    if not compiler:raise SystemExit('A C++23 Clang compiler is required')
    if not options.sdk:raise SystemExit('Pass --sdk or set IDASDK to the pinned SDK header root')
    sdk=Path(options.sdk)
    if (sdk/'src/include').is_dir():sdk=sdk/'src'
    if not (sdk/'include/pro.h').is_file():raise SystemExit('SDK root has no include/pro.h')
    platform=['-D__MAC__'] if sys.platform=='darwin' else ['-D__LINUX__'] if sys.platform.startswith('linux') else ['-D__NT__']
    domains=sorted(set(re.findall(r'#include <ida/(\w+)\.hpp>',UMBRELLA.read_text())))
    def scan(domain):
        path=ROOT/f'include/ida/{domain}.hpp';source_bytes=path.read_bytes();source=source_bytes.decode('utf-8')
        prefix=f'ida::{domain}' if domain not in ['core','error','address'] else 'ida'
        command=(['xcrun'] if sys.platform=='darwin' and not options.clang else [])+[compiler,'-std=c++23','-Iinclude','-I'+str(sdk/'include'),'-D__EA64__',*platform,'-x','c++','-Xclang','-ast-dump=json','-Xclang',f'-ast-dump-filter={prefix}','-fsyntax-only',str(path.relative_to(ROOT))]
        process=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
        if process.returncode:
            raise RuntimeError(domain+': '+process.stderr.replace(str(ROOT),'<repo-root>').replace(str(sdk),'<ida-sdk-root>'))
        entries=[]
        def spelling(node,without_body=False):
            span=node.get('range',{});begin=span.get('begin',{}).get('offset');endnode=span.get('end',{});end=endnode.get('offset')
            if begin is None or end is None:return ''
            stop=end+endnode.get('tokLen',0)
            if without_body:
                for child in node.get('inner',[]):
                    if child.get('kind')=='CompoundStmt':
                        stop=child.get('range',{}).get('begin',{}).get('offset',stop)
                        break
            text=source_bytes[begin:stop].decode('utf-8')
            text=re.sub(r'//[^\n]*|/\*.*?\*/','',text,flags=re.S)
            return re.sub(r'\s+',' ',text).strip()
        def walk(node,scope,access='public',is_root=False):
            if node.get('isImplicit'):return
            kind=node['kind'];name=node.get('name','')
            if kind=='AccessSpecDecl':return
            if kind in ['FunctionTemplateDecl','TypeAliasTemplateDecl','ClassTemplateDecl','FriendDecl']:
                if access=='public':
                    for child in node.get('inner',[]):
                        if child.get('kind') not in ['TemplateTypeParmDecl','NonTypeTemplateParmDecl']:
                            walk(child,scope,access)
                return
            if kind in ['NamespaceDecl']:
                nested=scope+[name] if name else scope
                for child in node.get('inner',[]):walk(child,nested,access)
                return
            if access!='public':return
            if kind in ['CXXRecordDecl','RecordDecl']:
                if not node.get('completeDefinition'):return
                qualified='::'.join(scope+[name])
                entries.append({'name':qualified,'kind':'type','signature':node.get('tagUsed','struct')})
                next_access='private' if node.get('tagUsed')=='class' else 'public'
                for child in node.get('inner',[]):
                    if child['kind']=='AccessSpecDecl':next_access=child['access']
                    else:walk(child,scope+[name],next_access)
                return
            kinds={'EnumDecl':'enum','EnumConstantDecl':'enum_case','FieldDecl':'field','FunctionDecl':'function','CXXMethodDecl':'method','CXXConstructorDecl':'constructor','CXXDestructorDecl':'destructor','CXXConversionDecl':'conversion','TypeAliasDecl':'alias','TypedefDecl':'alias','VarDecl':'constant'}
            if kind in kinds and name:
                # Clang offsets address UTF-8 bytes, not Unicode code points.
                text=spelling(node,without_body=True)
                entry={'name':'::'.join(scope+[name]),'kind':kinds[kind],'signature':node.get('type',{}).get('qualType',text)}
                entry['declaration']=text
                parameters=[]
                for child in node.get('inner',[]):
                    if child.get('kind')=='ParmVarDecl':
                        parameter={'name':child.get('name',''),'type':child.get('type',{}).get('qualType','')}
                        if 'init' in child:
                            declaration=spelling(child)
                            parameter['default']=declaration.partition('=')[2].strip()
                        parameters.append(parameter)
                if parameters:entry['parameters']=parameters
                if node.get('storageClass')=='static':entry['static']=True
                entries.append(entry)
                if kind=='EnumDecl':
                    for child in node.get('inner',[]):walk(child,scope+[name])
        for root in objects(process.stdout):
            if domain=='address':
                for child in root.get('inner',[]) if root['kind']=='NamespaceDecl' else [root]:
                    if child.get('name') in ['Address','AddressDelta','AddressSize','BadAddress','address']:
                        walk(child,['ida'])
            elif domain not in ['core','error']:
                walk(root,['ida'])
            else:
                # Filter included namespaces by declarations' local name tokens.
                for child in root.get('inner',[]) if root['kind']=='NamespaceDecl' else [root]:
                    name=child.get('name','')
                    declared_type=name and re.search(r'\b(?:class|struct|enum class|using|inline|constexpr)\s+'+re.escape(name)+r'\b',source)
                    declared_function=name and re.search(r'\b'+re.escape(name)+r'\s*\(',source)
                    if declared_type or declared_function:walk(child,['ida'])
        # Function-like export macros do not appear in Clang's declaration AST.
        # Include their complete definitions as independently mapped API entries.
        source_lines = source.splitlines()
        for index, line in enumerate(source_lines):
            definition = re.match(r'^#define (IDAX_[A-Z_]+)\(([^)\n]*)\)', line)
            if definition is None:
                continue
            name, formals = definition.groups()
            body = [line]
            while body[-1].rstrip().endswith('\\') and index + 1 < len(source_lines):
                index += 1
                body.append(source_lines[index])
            entries.append({
                'name': name, 'kind': 'macro',
                'signature': name + '(' + re.sub(r'\s+', ' ', formals).strip() + ')',
                'declaration': re.sub(r'\s+', ' ', '\n'.join(body).replace('\\\n', ' ')).strip(),
            })
        # Duplicate namespace declarations can appear in filtered AST streams.
        unique={json.dumps(x,sort_keys=True):x for x in entries}
        return {'domain':domain,'header':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes().replace(b'\r\n',b'\n')).hexdigest(),'declarations':sorted(unique.values(),key=lambda x:(x['name'],x['kind'],x['signature']))}
    with ThreadPoolExecutor(max_workers=min(8,len(domains))) as executor:results=list(executor.map(scan,domains))
    data={'schema_version':2,'authoritative_umbrella':str(UMBRELLA.relative_to(ROOT)),'domains':results}
    content=json.dumps(data,indent=2)+'\n'
    if options.check:
        if not OUTPUT.exists() or OUTPUT.read_text()!=content:raise SystemExit('C++ declaration inventory changed; repeat the Swift API mapping audit')
    else:OUTPUT.write_text(content)
    for d in results:print(d['domain'],len(d['declarations']))
    print('Total',sum(len(d['declarations']) for d in results))
if __name__=='__main__':main()

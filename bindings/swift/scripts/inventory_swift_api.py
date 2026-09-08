#!/usr/bin/env python3
"""Extract and normalize actual public Swift declarations from the built module.

Source locations are repository-relative. Compiler-generated identities and
locations are excluded from the stable declaration key; the complete callable
signature and generic/availability constraints remain review evidence.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / 'bindings/swift/swift_api_inventory.json'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true')
    parser.add_argument('--configuration',default='debug',choices=['debug','release'])
    parser.add_argument('--module-directory',type=Path)
    options=parser.parse_args()
    target=json.loads(subprocess.check_output(['swift','-print-target-info'],text=True))['target']['triple']
    if sys.platform=='darwin':target=target.split('-apple-')[0]+'-apple-macosx13.0'
    module=options.module_directory
    if module is None:
        binpath=subprocess.check_output(['swift','build','--build-system','native','--package-path',str(ROOT),'--configuration',options.configuration,'--show-bin-path'],text=True).strip()
        module=Path(binpath)/'Modules'
    with tempfile.TemporaryDirectory(prefix='idax-symbols-') as directory:
        command=['swift','symbolgraph-extract','-module-name','IDAX','-I',str(module),'-I',str(ROOT/'bindings/swift/Sources/CIDAX'),'-target',target,'-output-dir',directory,'-skip-synthesized-members']
        if sys.platform=='darwin':command+=['-sdk',subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip()]
        subprocess.run(command,check=True)
        symbols=[]
        for path in sorted(Path(directory).glob('IDAX*.symbols.json')):
            document=json.loads(path.read_text())
            for value in document['symbols']:
                uri=value.get('location',{}).get('uri')
                if not uri:continue
                source=Path(unquote(urlparse(uri).path)).resolve()
                try:relative=source.relative_to(ROOT)
                except ValueError:continue
                declaration=''.join(fragment['spelling'] for fragment in value.get('declarationFragments',[]))
                entry={'path':value['pathComponents'],'kind':value['kind']['identifier'],'declaration':declaration,'source':str(relative)}
                for key in ['functionSignature','swiftGenerics','swiftConstraints','availability']:
                    if key in value:entry[key]=value[key]
                # Native pointers or transport types must not be public.
                if any(token in declaration for token in ['UnsafePointer','UnsafeMutablePointer','UnsafeRawPointer','UnsafeMutableRawPointer','OpaquePointer','IdaxSwift','CIDAX.']):
                    raise SystemExit('Native transport leaked into public declaration: '+'.'.join(entry['path']))
                stable={'path':entry['path'],'kind':entry['kind'],'declaration':declaration}
                entry['id']=hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()[:20]
                symbols.append(entry)
        unique={value['id']:value for value in symbols}
        document={'schema_version':1,'module':'IDAX','declarations':sorted(unique.values(),key=lambda x:('.'.join(x['path']),x['kind'],x['declaration']))}
        content=json.dumps(document,indent=2)+'\n'
        if options.check:
            if not OUTPUT.exists() or OUTPUT.read_text()!=content:raise SystemExit('Public Swift declarations changed; repeat the semantic mapping audit')
        else:OUTPUT.write_text(content)
        print('Swift public declarations:',len(document['declarations']))

if __name__=='__main__':main()

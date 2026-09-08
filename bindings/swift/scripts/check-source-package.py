#!/usr/bin/env python3
"""Audit a Git source archive, then build its extracted Swift package.

The configured native archive/runtime remain external prerequisites. This test
checks that the exported source tree includes every private transport header and
can compile as a SwiftPM dependency without the original checkout or build tree.
Use --index before committing; CI checks the committed tree by default.
"""
from __future__ import annotations
import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from sanitize_ida_fixture import sensitive_categories

FORBIDDEN_PARTS={'.git','.build','.swiftpm','node_modules','target','ida-sdk','ida-installer','__pycache__'}
FORBIDDEN_FILE=re.compile(r'(?:^|/)(?:libida(?:lib)?(?:64)?\.(?:so(?:\.\d+)*|dylib)|ida(?:lib)?(?:64)?\.dll|[^/]*\.hexlic)$',re.I)
PRODUCT_SUFFIXES={'.a','.o','.obj','.so','.dylib','.dll','.lib','.exe','.node','.pyc','.pdb','.swiftmodule','.swiftdoc','.pc'}

def contained_link_target(name, linkname):
    target=PurePosixPath(linkname)
    if target.is_absolute():raise ValueError('Absolute source archive link')
    resolved=PurePosixPath(posixpath.normpath(str(PurePosixPath(name).parent/target)))
    if len(resolved.parts)<2 or resolved.parts[0]!='idax':
        raise ValueError('Source archive link escapes its root')
    return resolved

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index',action='store_true',help='Audit the exact staged tree instead of HEAD')
    parser.add_argument('--audit-only',action='store_true',help='Inspect contents without building the extracted Swift package')
    args=parser.parse_args()
    reference=subprocess.check_output(['git','write-tree'],cwd=ROOT,text=True).strip() if args.index else 'HEAD'
    payload=subprocess.check_output(['git','archive','--format=tar','--prefix=idax/',reference],cwd=ROOT)
    with tempfile.TemporaryDirectory(prefix='idax-swift-source-') as temporary:
        destination=Path(temporary);names=set();links=[];count=0
        with tarfile.open(fileobj=io.BytesIO(payload),mode='r:') as archive:
            for entry in archive:
                path=PurePosixPath(entry.name)
                if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!='idax':
                    raise SystemExit('Unsafe source archive member')
                relative=PurePosixPath(*path.parts[1:]);name=str(relative)
                if (any(part in FORBIDDEN_PARTS for part in relative.parts) or any(part=='build' or part.startswith('build-') for part in relative.parts[:-1])) or FORBIDDEN_FILE.search(name):
                    raise SystemExit('Forbidden source archive member: '+name)
                if relative.suffix.lower() in PRODUCT_SUFFIXES and not name.startswith('tests/fixtures/'):
                    raise SystemExit('Compiled/local product in source archive: '+name)
                if entry.islnk():raise SystemExit('Source archive contains a hard link: '+name)
                if entry.issym():
                    try:target=contained_link_target(entry.name,entry.linkname)
                    except ValueError as error:raise SystemExit(str(error)+': '+name) from error
                    links.append((entry.name,name,target))
                    continue
                if entry.isdir():continue
                if not entry.isfile():raise SystemExit('Unsupported source archive member: '+name)
                source=archive.extractfile(entry)
                if source is None:raise SystemExit('Unreadable source archive member: '+name)
                data=source.read();categories=sensitive_categories(data,binary=b'\0' in data)
                if categories:raise SystemExit('Source archive privacy failure: '+name+' ('+', '.join(categories)+')')
                output=destination/entry.name;output.parent.mkdir(parents=True,exist_ok=True);output.write_bytes(data)
                output.chmod(entry.mode & 0o777);names.add(name);count+=1
        # Git exports the Rust packages' LICENSE files as links to their shared
        # license. Materialize only direct links to audited regular members;
        # directories, missing targets and link chains are not extractable.
        regular_names=set(names)
        for archive_name,name,target in links:
            relative_target=PurePosixPath(*target.parts[1:]).as_posix()
            if relative_target not in regular_names:
                raise SystemExit('Source archive link does not target a regular member: '+name)
            output=destination/archive_name;output.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(destination/target,output)
            names.add(name);count+=1
        required={'Package.swift','CMakeLists.txt','README.md','include/ida/idax.hpp',
                  'bindings/rust/idax-sys/shim/idax_shim.h','bindings/rust/idax-sys/shim/idax_shim.cpp',
                  'bindings/swift/README.md','bindings/swift/CONTRACT.md',
                  'bindings/swift/Sources/CIDAX/module.modulemap','bindings/swift/Sources/CIDAX/include/CIDAX.h',
                  'bindings/swift/cpp_api_inventory.json','bindings/swift/swift_api_inventory.json',
                  'bindings/swift/scripts/check_api_mapping.py','bindings/swift/scripts/generate_values.py',
                  'bindings/swift/CMakeLists.txt','bindings/swift/idax-swift.pc.in',
                  'bindings/swift/module_entry.cpp.in','bindings/swift/module_bridge.cpp.in',
                  'bindings/swift/scripts/build-and-test.sh','bindings/swift/scripts/build-module.py',
                  'bindings/swift/scripts/check-consumer.py','bindings/swift/scripts/check-module-host.py'}
        # The source archive must also retain the complete private C++ bridge,
        # although the extracted Swift-only compile consumes its C headers.
        required.update(path.relative_to(ROOT).as_posix() for path in (ROOT/'bindings/swift/bridge').iterdir()
                        if path.is_file() and path.suffix in {'.h','.hpp','.cpp'})
        missing=sorted(required-names)
        if missing:raise SystemExit('Source archive lacks required files: '+', '.join(missing))
        extracted=destination/'idax'
        subprocess.run([sys.executable,str(extracted/'bindings/swift/scripts/generate_values.py'),'--check'],check=True)
        subprocess.run([sys.executable,str(extracted/'bindings/swift/scripts/check_api_mapping.py'),'--check'],check=True)
        description=json.loads(subprocess.check_output(['swift','package','--package-path',str(extracted),'describe','--type','json'],text=True))
        for target in description['targets']:
            base=extracted/target['path']
            if not base.is_dir():raise SystemExit('Swift package target missing from archive: '+target['name'])
            for source in target.get('sources',[]):
                if not (base/source).is_file():raise SystemExit('Swift package source missing from archive: '+source)
        if not args.audit_only:
            if not os.environ.get('PKG_CONFIG_PATH'):raise SystemExit('Set PKG_CONFIG_PATH to the external native transport configuration')
            subprocess.run(['swift','build','--build-system','native','--package-path',str(extracted),'--target','IDAX'],check=True)
        print(f'Swift source package: PASS ({count} files; extracted package '+('audited' if args.audit_only else 'compiled')+')')

if __name__=='__main__':main()

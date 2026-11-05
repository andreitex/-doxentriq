#!/usr/bin/env python3
"""Verify a source test snapshot and extract only regular files into a new directory."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile


if __name__=='__main__':
    archive,manifest_path,destination=map(Path,sys.argv[1:4])
    expected=sys.argv[4]
    metadata=json.loads(Path('/etc/autosoft/installation.json').read_text())
    data=Path(metadata['data_dir'])
    if os.geteuid()!=0 or destination.exists() or data/'validation' not in destination.resolve().parents: raise SystemExit('Use root and a new encrypted validation directory')
    manifest=json.loads(manifest_path.read_text())
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected or manifest['archiveSha256']!=expected: raise SystemExit('Source snapshot hash mismatch')
    destination.mkdir(mode=0o755)
    with tarfile.open(archive) as tar:
        total=0
        for member in tar:
            resolved=(destination/member.name).resolve()
            total+=member.size
            if destination.resolve() not in resolved.parents or not member.isfile() or total>256*1024**2: raise SystemExit('Unsafe source archive member')
        tar.extractall(destination)
    files={str(path.relative_to(destination)).replace(os.sep,'/'):hashlib.sha256(path.read_bytes()).hexdigest() for path in destination.rglob('*') if path.is_file()}
    if files!=manifest['files']: raise SystemExit('Extracted source differs from the reviewed manifest')
    for path in [destination]+list(destination.rglob('*')):
        os.chown(path,10001,10001)
        os.chmod(path,0o755 if path.is_dir() else 0o644)
    proof=Path(str(destination)+'.manifest.json')
    with proof.open('xb') as handle:
        handle.write(manifest_path.read_bytes())
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(proof,0o600)
    print('Verified source snapshot:',len(files),'regular files',expected)

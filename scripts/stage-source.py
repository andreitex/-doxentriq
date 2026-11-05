#!/usr/bin/env python3
"""Create a reviewed source-only test bundle, excluding secrets and runtime output."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile


if __name__=='__main__':
    root=Path(__file__).resolve().parent.parent
    output=Path(sys.argv[1]).resolve()
    if output.exists(): raise SystemExit('Source test bundle must be a new file')
    files=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
    hashes={}
    blocked={'.git','.local','.local-data','.cache','node_modules','__pycache__','secrets','artifacts','generated','data','dist'}
    with tarfile.open(output,'w:gz') as archive:
        for relative in sorted(set(files)-{''}):
            path=Path(relative)
            if path.is_absolute() or '..' in path.parts or set(path.parts)&blocked or relative.startswith(('deploy/verification/','deploy/releases/')) or path.suffix.lower() in {'.key','.pem','.ppk','.pyc','.luks','.log'} or (path.name.startswith('.env') and path.name!='.env.example') or path.name=='.npmrc': continue
            source=root/path
            if source.is_symlink() or root not in source.resolve().parents or not source.is_file(): raise SystemExit('Unsafe reviewed source path')
            content=source.read_bytes()
            if path.suffix=='.sh' and b'\r' in content:
                raise SystemExit('Linux shell source requires LF line endings: '+relative)
            hashes[relative]=hashlib.sha256(content).hexdigest()
            archive.add(source,arcname=relative,recursive=False)
    manifest=dict(schemaVersion=1,files=hashes,archiveSha256=hashlib.sha256(output.read_bytes()).hexdigest())
    output.with_suffix(output.suffix+'.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'files':len(hashes),'bytes':output.stat().st_size,'archiveSha256':manifest['archiveSha256']}))

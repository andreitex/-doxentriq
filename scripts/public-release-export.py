#!/usr/bin/env python3
"""Prepare a new, auditable public source candidate; never publish or overwrite."""
from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from urllib.parse import unquote, urlsplit

spec = importlib.util.spec_from_file_location('public_check', Path(__file__).with_name('public-release-check.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)

ROOT_FILES = {'.dockerignore', '.gitattributes', '.gitignore', 'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'RELEASING.md', 'LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'NOTICE', 'NOTICE.md', 'package.json', 'package-lock.json', 'tsconfig.json'}
SOURCE_DIRS = {'.github', 'apps', 'database', 'deploy', 'docs', 'models', 'packages', 'scripts', 'services', 'templates', 'test', 'tests', 'tools'}
EXCLUDED_FILES = {'docs/trial-access.md', 'scripts/start-trial-access.ps1', 'scripts/stop-trial-access.ps1', 'scripts/open-trial-direct-access.ps1'}
EXCLUDED_PREFIXES = ('deploy/verification/', 'deploy/releases/')
CARRIERS = {'scripts/company_seed_backend_native_client_v1.py', 'scripts/company_seed_backend_native_client_v2.py', 'scripts/company_seed_backend_native_client_v3.py', 'scripts/company_seed_runner_native_client_v1.py'}
PUBLIC_DOCS = {
    'docs/implementation-status.md': '''# Public source preview status

This source preview is not a production acceptance certificate. The project
implements chat workflows, application pipelines, identity, isolation, spending
controls and release management. Completion must be established by current tests
and native installation evidence for the exact released source and images.

Outstanding release acceptance includes the complete Debian/Rocky OS matrix,
reboot/interrupted-install recovery, current security scans, existing-data migration
rehearsal and compatible rollback, backup restoration, live identity integrations,
and a usability trial with a nontechnical administrator.

Company installation receipts and historical customer/trial records are deliberately
excluded from this source distribution. They must not be used as proof that a new
installation passed. See [release preparation](../RELEASING.md) and the current
[README](../README.md) for supported scope and installation limitations.
''',
    'docs/provider-preflight.md': '''# Provider preflight and qualification

The IT installer configures provider credentials through protected files on the
installation host. Keep credentials out of chat, command-line arguments and source.
The diagnostic below accepts root-owned regular files with permissions 0400 or 0600,
rejects linked or oversized input, and requests only the provider model-list endpoint.

```sh
sudo python3 -I -B scripts/provider-preflight.py \\
  --openai-key-file /run/credentials/openai-key \\
  --anthropic-key-file /run/credentials/anthropic-key
```

Either provider is optional. A successful preflight proves authentication to that
endpoint; it does not mark a model qualified, enable generation or prove billing.
The optional Google client-file check parses configuration only; real OAuth login
with the registered callback remains a separate acceptance test.

Review provider model IDs, prices and reasoning capabilities before qualification.
`npm run qualify:models -- --dry-run` previews evaluation reservations without a
paid request. Real qualification requires explicit per-call, per-suite and total
limits and the approved shared monthly accounting path. Never bypass an unknown
charge by clearing a reservation or creating a second ledger.

See [model routing](model-routing.md), [shared testing allowance](shared-testing-allowance.md)
and [release preparation](../RELEASING.md). No customer's keys, ledger, billing
amounts or historical model qualification are included in this public source.
''',
    'docs/shared-testing-allowance.md': '''# Shared testing allowance

Company diagnostics and administrator chat workflows must share one approved
monthly allowance. A second tool must not create an independent allowance that
can spend the same budget twice. Setup requires explicit monthly and per-request
limits; administrators approve an increase through the protected workflow.

Reserve estimated cost before execution. Settle only confirmed usage; retain an
unknown outcome and its reservation until it is reconciled. A conservative debit
requires explicit approval and preserves the original uncertain billing records.
Do not replay an uncertain provider request to find out whether it completed.

Monthly handover, expiration and renewal require current acceptance tests on the
shared durable store. The public source contains no customer ledger, provider key,
previous testing balance or authority to spend on an existing installation.

See [model routing](model-routing.md), [provider preflight](provider-preflight.md)
and [release preparation](../RELEASING.md).
''',
}
LINK = re.compile(r'(!?)\[([^\]\n]*)\]\(([^)\n]+)\)')


def allowed(name: str) -> bool:
    path=PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
        raise ValueError('Unsafe candidate path')
    return (name in ROOT_FILES or (len(path.parts)>1 and path.parts[0] in SOURCE_DIRS)) and name not in EXCLUDED_FILES and not name.startswith(EXCLUDED_PREFIXES) and not any(part in check.SKIP_DIRECTORIES | {'secrets', '.aws', 'backups', 'restores'} for part in path.parts)


def regular(root: Path, name: str) -> Path:
    current=root
    for part in PurePosixPath(name).parts:
        current/=part
        metadata=current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or (getattr(metadata, 'st_file_attributes', 0)&0x400):
            raise ValueError('Linked source is not exportable: '+name)
    if not current.is_file() or current.stat().st_size>check.MAX_FILE_BYTES:
        raise ValueError('Unreviewable source: '+name)
    return current


def resolve_link(name: str, target: str) -> str | None:
    target=target.strip().split(' "',1)[0].strip('<>')
    parsed=urlsplit(target)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    target=unquote(parsed.path)
    parts=list(PurePosixPath(name).parent.parts)
    for part in PurePosixPath(target).parts:
        if part=='..':
            if not parts: raise ValueError('Document link escapes source root: '+name)
            parts.pop()
        elif part not in ('.','/'):
            parts.append(part)
    return '/'.join(parts)


def transform(name: str, data: bytes, selected: set[str]) -> tuple[bytes,list[str]]:
    reasons=[]
    if name in PUBLIC_DOCS:
        data=PUBLIC_DOCS[name].encode('utf-8')
        reasons.append('Replace private installation chronology with public scope and procedures')
    if name in CARRIERS:
        text=data.decode('utf-8')
        text,count=re.subn(r"(?m)^ROOT=Path\([^\n]+\)\r?$", 'ROOT=Path(__file__).resolve().parents[1]',text)
        if count!=1: raise ValueError('Carrier root declaration changed: '+name)
        for field in ('SESSION','HOSTKEY'):
            text,count=re.subn(r'(?m)^'+field+r'=[^\n]+\r?$',field+"=''  # Configure only for an explicitly approved company diagnostic.",text)
            if count!=1: raise ValueError('Carrier station declaration changed: '+name)
        if ' need(bool(SESSION) and bool(HOSTKEY))' not in text:
            text,count=re.subn(r'(?m)^(def dispatch_once\([^\n]+\):\r?\n)',r'\1 need(bool(SESSION) and bool(HOSTKEY))\n',text)
            if count!=1: raise ValueError('Carrier dispatch boundary changed: '+name)
        data=text.encode('utf-8')
        reasons.append('Use checkout-relative source and disable historical operator-specific SSH station defaults')
    if name=='scripts/test-foundation.py':
        text=data.decode('utf-8')
        text,count=re.subn(r"host='[^']+'", "host=output(['hostname'])",text)
        if count!=1 and "host=output(['hostname'])" not in text:raise ValueError('Foundation metadata declaration changed')
        text=re.sub(r"reason='VM has less than16GiB RAM;[^']+'", "reason='Foundation checks alone do not qualify complete platform installation'",text)
        data=text.encode('utf-8')
        reasons.append('Report the actual test host instead of historical trial host metadata')
    if name.endswith('.md'):
        text=data.decode('utf-8')
        def replace(match):
            target=resolve_link(name,match.group(3))
            if target and target not in selected and (target in EXCLUDED_FILES or target.startswith(EXCLUDED_PREFIXES) or '/.local/' in '/'+target):
                reasons.append('Remove link to private installation evidence or trial access tooling')
                return match.group(2)+' (private installation record; not distributed)'
            return match.group(0)
        data=LINK.sub(replace,text).encode('utf-8')
    return data,sorted(set(reasons))


def export(root: Path, output: Path) -> dict:
    root=root.resolve()
    output=output.absolute()
    if output.exists() or output.is_symlink():raise ValueError('Output must be a new directory; existing artifacts are preserved')
    parent=output.parent
    while parent!=parent.parent:
        if parent.is_symlink() or (getattr(parent.stat(),'st_file_attributes',0)&0x400):raise ValueError('Output parent must not be linked')
        parent=parent.parent
    names=check.candidates(root)
    selected={name for name in names if allowed(name)}
    contents={}
    for name in sorted(selected):
        source=regular(root,name)
        data=source.read_bytes()
        if len(data)>check.MAX_FILE_BYTES:raise ValueError('Source grew past review limit')
        result,reasons=transform(name,data,selected)
        contents[name]=(data,result,reasons,source.stat().st_mode)
    broken=[]
    for name,(_,data,_,_) in contents.items():
        if not name.endswith('.md'):continue
        for match in LINK.finditer(data.decode('utf-8')):
            target=resolve_link(name,match.group(3))
            if target and target not in selected and not any(path.startswith(target.rstrip('/')+'/') for path in selected):
                broken.append({'path':name,'target':target})
    output.mkdir(mode=0o700)
    manifest=[]
    for name,(original,data,reasons,mode) in sorted(contents.items()):
        target=output/name
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as file:file.write(data)
        os.chmod(target,stat.S_IMODE(mode)&0o777)
        manifest.append({'path':name,'sourceSha256':hashlib.sha256(original).hexdigest(),'exportSha256':hashlib.sha256(data).hexdigest(),'transformations':reasons})
    audit=check.inspect(output,sorted(selected))
    result={'schemaVersion':1,'status':'source_candidate_not_published','licenseSelected':any(n in selected for n in {'LICENSE','LICENSE.md','LICENSE.txt','COPYING'}),'fileCount':len(manifest),'excludedFileCount':len(names)-len(selected),'transformedFileCount':sum(bool(v['transformations']) for v in manifest),'publicSourceCheck':audit,'brokenDocumentationLinks':broken,'files':manifest}
    (output/'PUBLIC-SOURCE.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        result=export(args.root,args.output)
    except (OSError,ValueError) as error:
        print(json.dumps({'status':'refused','reason':str(error)}))
        return 2
    print(json.dumps({k:v for k,v in result.items() if k!='files'},indent=2))
    return 0 if result['publicSourceCheck']['ready'] and not result['brokenDocumentationLinks'] else 1


if __name__=='__main__':
    sys.exit(main())

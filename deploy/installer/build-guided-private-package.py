"""Produce one authenticated-delivery package for fresh private installation.

This only assembles protected company source. It does not sign, download,
install, activate or declare qualification. Independent delivery authenticates
the emitted entry before an IT operator runs it.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
UNKNOWN=[]
MAX_PACKAGE=4*1024**2
MAX_GUIDED_ENTRY=40*1024


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def protected_read(path,maximum=131072):
    path=Path(path)
    if not path.is_absolute() or UNKNOWN:raise ValueError('protected-company-source-required')
    parents={p:p.lstat()for p in path.parents};before=path.lstat()
    if any(not stat.S_ISDIR(s.st_mode)or s.st_uid!=0 or s.st_gid!=0 or s.st_mode&0o022 for s in parents.values()):raise ValueError('protected-source-ancestry')
    if not stat.S_ISREG(before.st_mode)or before.st_uid!=0 or before.st_gid!=0 or before.st_nlink!=1 or before.st_mode&0o022 or not 0<before.st_size<=maximum:raise ValueError('protected-source-file')
    identity=lambda s:tuple(getattr(s,k)for k in FIELDS)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        if identity(os.fstat(fd))!=identity(before):raise ValueError('source-replaced')
        raw=bytearray()
        while len(raw)<before.st_size:
            part=os.pread(fd,min(65536,before.st_size-len(raw)),len(raw))
            if not part:raise ValueError('source-short-read')
            raw.extend(part)
        if os.pread(fd,1,len(raw))or identity(os.fstat(fd))!=identity(before)or identity(path.lstat())!=identity(before):raise ValueError('source-changed')
        if any(identity(p.lstat())!=identity(s)for p,s in parents.items()):raise ValueError('source-ancestor-changed')
        return bytes(raw)
    finally:
        try:os.close(fd)
        except BaseException:UNKNOWN.append(fd);raise


def module(name,raw):
    value=ModuleType(name);value.__file__='<trusted guided producer '+name+'>'
    exec(compile(raw,value.__file__,'exec'),value.__dict__)
    return value


def entry(root,records,*,reader):
    expected={'company-install.sh','company_install.py','company-native-retention.py',
              'company-prepare.sh','company-private-quota.sh','installation-status.py'}
    intake={'company-request-intake.py','guided-request-defaults.json','company-signing-public-key.pem'}
    if type(records)is not dict or set(records)not in(expected,expected|intake) or any(type(raw)is not bytes or not raw for raw in records.values()):raise ValueError('exact-guided-components-required')
    pins={name:pin(raw)for name,raw in sorted(records.items())}
    raw=reader(Path(root)/'deploy/installer/company-guided-private.sh',32768)
    lock=reader(Path(root)/'scripts/install-lock.sh',32768)
    for marker in(b'# @EMBED_INSTALL_LOCK@',b'# @GUIDED_PACKAGE_FILES@',b'@GUIDED_PACKAGE_SHA256@',b'@REQUEST_INTAKE_AVAILABLE@'):
        if raw.count(marker)!=1:raise ValueError('guided-template-marker')
    lines='\n'.join('  _gp_file '+name+' '+row['sha256']+' '+str(row['bytes'])for name,row in pins.items()).encode('ascii')
    package_sha=hashlib.sha256((json.dumps(pins,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest().encode('ascii')
    raw=raw.replace(b'# @EMBED_INSTALL_LOCK@',lock).replace(b'# @GUIDED_PACKAGE_FILES@',lines).replace(b'@GUIDED_PACKAGE_SHA256@',package_sha)
    raw=raw.replace(b'@REQUEST_INTAKE_AVAILABLE@',b'true' if intake<=set(records) else b'false')
    if len(raw)>MAX_GUIDED_ENTRY:raise ValueError('guided-entry-size')
    return raw


def assemble(root,fingerprint,*,reader=protected_read,host_catalogs=None,intake_defaults=None,public_key=None):
    if type(host_catalogs)is not dict or set(host_catalogs)not in({'engine'},{'tools','packages'}):raise ValueError('qualified-host-catalogs-required')
    if (intake_defaults is None)!=(public_key is None):raise ValueError('complete-intake-delivery-inputs-required')
    root=Path(root);captures={}
    def captured(path,maximum=131072):
        path=Path(path)
        if path not in captures:captures[path]=reader(path,maximum)
        raw=captures[path]
        if type(raw)is not bytes or not 0<len(raw)<=maximum:raise ValueError('captured-source-size')
        return raw
    foundation=module('foundation',captured(root/'deploy/installer/build-package.py'))
    native=module('native',captured(root/'deploy/installer/build-native-retention-package.py'))
    records=foundation.assemble(root,fingerprint,reader=captured,host_catalogs=host_catalogs)
    options={'engine_catalog':host_catalogs['engine']}if 'engine'in host_catalogs else dict(host_tool_catalog=host_catalogs['tools'],host_package_catalog=host_catalogs['packages'])
    worker=native.assemble(root,fingerprint,reader=captured,**options)
    records.update({'company-native-retention.py':worker,
        'company-prepare.sh':native.assemble_entry(root,worker,reader=captured,preparation=True),
        'company-private-quota.sh':native.assemble_entry(root,worker,reader=captured,quota=True),
        'installation-status.py':captured(root/'scripts/installation-status.py')})
    intake=None
    if intake_defaults is not None:
        template=captured(root/'deploy/installer/company_request_intake.py')
        intake=module('request_intake',template)
        records.update({'guided-request-defaults.json':intake_defaults,'company-signing-public-key.pem':public_key,
            'company-request-intake.py':intake.build(template,records['company_install.py'],
                captured(root/'deploy/installer/company_full_cli_request.py'),intake_defaults,public_key)})
    records['company-guided-private.sh']=entry(root,records,reader=captured)
    if intake is not None:records['guided-delivery.txt']=intake.delivery_receipt(records)
    if sum(map(len,records.values()))>MAX_PACKAGE:raise ValueError('guided-package-size')
    for path,raw in captures.items():
        if reader(path,len(raw))!=raw:raise ValueError('company-source-changed-during-assembly')
    return records


def placement(root,records,*,reader=protected_read):
    """Separate company-authenticated pre-Python placer; no candidate imports."""
    root=Path(root)
    limits={'deploy/installer/company_guided_placement.py':32768,
            'deploy/installer/company-place-guided.sh':24576,
            'deploy/installer/company_request_intake.py':131072,'scripts/install-lock.sh':32768}
    captured={name:reader(root/name,limit)for name,limit in limits.items()}
    for name,raw in captured.items():
        if type(raw)is not bytes or not 0<len(raw)<=limits[name]:raise ValueError('placement-source-size')
    producer=module('guided_placement',captured['deploy/installer/company_guided_placement.py'])
    intake=module('guided_placement_intake',captured['deploy/installer/company_request_intake.py'])
    entry=producer.build(captured['deploy/installer/company-place-guided.sh'],captured['scripts/install-lock.sh'],records,intake=intake)
    for name,raw in captured.items():
        if reader(root/name,len(raw))!=raw:raise ValueError('placement-source-changed')
    return {'doxentriq-place-guided.sh':entry}


def validate_output_destination(destination):
    """Read-only admission shared by pair preflight and each final emission."""
    if os.name!='posix'or os.geteuid()!=0 or os.getegid()!=0 or UNKNOWN:raise ValueError('company-linux-root-producer-required')
    destination=Path(destination)
    if not destination.is_absolute()or os.path.lexists(destination):raise ValueError('fresh-package-destination-required')
    for parent in destination.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:raise ValueError('protected-output-ancestor-required')
    return destination


def emit(destination,records):
    destination=validate_output_destination(destination)
    destination.mkdir(mode=0o700)
    for name,raw in records.items():
        fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
        try:
            offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:offset+65536])
                if count<=0:raise ValueError('package-short-write')
                offset+=count
            os.fsync(fd)
        finally:
            try:os.close(fd)
            except BaseException:UNKNOWN.append(fd);raise
        if protected_read(destination/name,MAX_PACKAGE)!=raw:raise ValueError('package-readback-mismatch')
    for directory in(destination,destination.parent):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:
            try:os.close(fd)
            except BaseException:UNKNOWN.append(fd);raise
    return {name:pin(raw)for name,raw in records.items()}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('root',type=Path);p.add_argument('destination',type=Path);p.add_argument('--fingerprint',required=True)
    p.add_argument('--engine-catalog',required=True,type=Path);p.add_argument('--engine-catalog-sha256',required=True)
    p.add_argument('--request-defaults',type=Path);p.add_argument('--request-defaults-sha256')
    p.add_argument('--public-key',type=Path)
    p.add_argument('--placement-destination',type=Path,help='Fresh separate directory for the independently authenticated pre-Python delivery placer')
    a=p.parse_args(argv)
    if os.name!='posix'or os.geteuid()!=0 or os.getegid()!=0:raise ValueError('company-linux-root-producer-required')
    if not a.root.is_absolute()or not a.engine_catalog.is_absolute()or a.engine_catalog.resolve(strict=True)!=a.engine_catalog or a.engine_catalog.is_relative_to(a.root.resolve(strict=True)):raise ValueError('independent-company-catalog-required')
    catalog=protected_read(a.engine_catalog,65536)
    if pin(catalog)['sha256']!=a.engine_catalog_sha256:raise ValueError('catalog-digest-mismatch')
    defaults=public_key=None
    if any(value is not None for value in(a.request_defaults,a.request_defaults_sha256,a.public_key)):
        if any(value is None for value in(a.request_defaults,a.request_defaults_sha256,a.public_key)):raise ValueError('complete-intake-delivery-inputs-required')
        defaults=protected_read(a.request_defaults,4096);public_key=protected_read(a.public_key,4096)
        if pin(defaults)['sha256']!=a.request_defaults_sha256:raise ValueError('independent-request-defaults-digest-mismatch')
    if a.placement_destination is not None:
        if defaults is None or not a.placement_destination.is_absolute()or not a.destination.is_absolute():raise ValueError('placement-requires-intake-and-absolute-outputs')
        first=a.destination.resolve();second=a.placement_destination.resolve()
        if first==second or first.is_relative_to(second)or second.is_relative_to(first):raise ValueError('separate-placement-output-required')
        if os.path.lexists(first)or os.path.lexists(second):raise ValueError('fresh-placement-outputs-required')
        # Refuse predictable second-output failures before creating either half.
        # emit repeats the same admission immediately before its own mkdir.
        validate_output_destination(a.destination)
        validate_output_destination(a.placement_destination)
    records=assemble(a.root,a.fingerprint,host_catalogs={'engine':catalog},intake_defaults=defaults,public_key=public_key)
    placement_records=placement(a.root,records)if a.placement_destination is not None else None
    pins=emit(a.destination,records)
    placement_pins=emit(a.placement_destination,placement_records)if placement_records is not None else None
    result=dict(scope='COMPANY_GUIDED_PRIVATE_PACKAGE_ONLY',files=pins,
        deliveryReceiptSha256=pins['guided-delivery.txt']['sha256'] if 'guided-delivery.txt' in pins else None,
        fullInstallerAvailable=False,publicStartupAvailable=False)
    if placement_pins is not None:result['placementFiles']=placement_pins
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()

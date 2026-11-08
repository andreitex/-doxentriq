"""Emit the two externally trusted company foundation entry files; never sign/install."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

TRUSTED = {name:'scripts/'+name for name in ('verify-release.py','installer_materialize.py','installer_parent.py')}
TRUSTED.update({name:'deploy/installer/'+name for name in ('company_native_station.py','company_host_tool_profiles.py','company_host_packages.py','company_host_package_runtime.py','company_engine_packages.py','company_engine_native.py','company_engine_elf.py')})
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
UNRELEASED=[]

def protected_read(path, maximum=131072):
    path=Path(path)
    if not path.is_absolute() or UNRELEASED:raise ValueError('package-source-unavailable')
    ancestors={parent:parent.lstat() for parent in path.parents}
    for info in ancestors.values():
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode)&0o022:
            raise ValueError('package-source-ancestry')
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode)&0o022 or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
        raise ValueError('package-source-unavailable')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0)|getattr(os,'O_BINARY',0))
    try:
        opened=os.fstat(fd);raw=bytearray()
        while len(raw) <= maximum:
            part=os.read(fd,min(65536,maximum+1-len(raw)))
            if not part:break
            raw.extend(part)
        after=os.fstat(fd);final=path.lstat()
    finally:
        try:os.close(fd)
        except BaseException:UNRELEASED.append(fd);raise
    if any(getattr(before,k) != getattr(final,k) or getattr(opened,k) != getattr(after,k) for k in FIELDS) or any(getattr(before,k) != getattr(opened,k) for k in FIELDS if k != 'st_ctime_ns') or len(raw) != before.st_size:
        raise ValueError('package-source-changed')
    for parent,info in ancestors.items():
        if any(getattr(info,k) != getattr(parent.lstat(),k) for k in FIELDS):raise ValueError('package-source-ancestry-changed')
    return bytes(raw)

def assemble(root, fingerprint, *, reader=protected_read, host_catalogs=None):
    if type(fingerprint) is not str or re.fullmatch('[a-f0-9]{64}',fingerprint) is None:
        raise ValueError('independent-company-fingerprint-required')
    root=Path(root)
    rows={}
    for name in TRUSTED:
        raw=reader(root/TRUSTED[name])
        rows[name]=dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),base64=base64.b64encode(raw).decode())
    worker=reader(root/'deploy/installer/company_install.py')
    marker=b'TRUSTED_CODE = {}  # @TRUSTED_CODE@'
    if worker.count(marker) != 1 or worker.count(b"COMPANY_FINGERPRINT = '@COMPANY_FINGERPRINT@'") != 1:
        raise ValueError('package-template-unavailable')
    worker=worker.replace(marker,b'TRUSTED_CODE = '+repr(rows).encode()).replace(b'@COMPANY_FINGERPRINT@',fingerprint.encode())
    catalog_marker=b'HOST_CATALOGS = None  # @COMPANY_HOST_CATALOGS@'
    if worker.count(catalog_marker)!=1:raise ValueError('host-catalog-template-unavailable')
    captured=None
    if host_catalogs is not None:
        if type(host_catalogs) is not dict or set(host_catalogs) not in ({'tools','packages'},{'engine'}):raise ValueError('one-independent-host-catalog-family-required')
        # The CLI protected-reader checked independent expected digests. Validate
        # both schemas and every package/tool pairing before emitting authority.
        from types import ModuleType
        loaded={}
        for name in ('company_host_tool_profiles.py','company_host_packages.py','company_engine_packages.py'):
            code=base64.b64decode(rows[name]['base64'],validate=True);mod=ModuleType('producer_'+name);exec(compile(code,name,'exec'),mod.__dict__);loaded[name]=mod
        profiles=loaded['company_host_tool_profiles.py'];packages=loaded['company_host_packages.py']
        if set(host_catalogs)=={'engine'}:
            loaded['company_engine_packages.py'].decode(host_catalogs['engine'],expected_catalog_sha256=hashlib.sha256(host_catalogs['engine']).hexdigest())
        else:
            tools=profiles.decode(host_catalogs['tools'],expected_catalog_sha256=hashlib.sha256(host_catalogs['tools']).hexdigest())
            catalog=packages.decode(host_catalogs['packages'],hashlib.sha256(host_catalogs['packages']).hexdigest(),profiles)
            for profile in catalog['profiles']:
                binding=profiles.bind(host_catalogs['tools'],expected_catalog_sha256=hashlib.sha256(host_catalogs['tools']).hexdigest(),observed_platform=profile['platform'])
                packages.bind(host_catalogs['packages'],expected_catalog_sha256=hashlib.sha256(host_catalogs['packages']).hexdigest(),observed_platform=profile['platform'],host_tools=binding,profiles=profiles)
        captured={name:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),base64=base64.b64encode(raw).decode()) for name,raw in host_catalogs.items()}
    worker=worker.replace(catalog_marker,b'HOST_CATALOGS = '+repr(captured).encode('ascii'))
    entry=reader(root/'deploy/installer/company-install.sh')
    lock=reader(root/'scripts/install-lock.sh')
    if entry.count(b'# @EMBED_INSTALL_LOCK@') != 1 or entry.count(b'@WORKER_SHA256@') != 1:
        raise ValueError('package-template-unavailable')
    if entry.count(b'@HOST_CATALOGS_AVAILABLE@')!=1:raise ValueError('host-catalog-entry-template-unavailable')
    if entry.count(b'@HOST_CATALOG_FAMILY@')!=1:raise ValueError('host-catalog-family-template-unavailable')
    entry=entry.replace(b'@HOST_CATALOG_FAMILY@',b'company-v2' if captured is not None and set(captured)=={'engine'} else b'vendor-v1')
    entry=entry.replace(b'@HOST_CATALOGS_AVAILABLE@',b'true' if captured is not None else b'false')
    entry=entry.replace(b'# @EMBED_INSTALL_LOCK@',lock).replace(b'@WORKER_SHA256@',hashlib.sha256(worker).hexdigest().encode())
    if len(worker) > 524288 or len(entry) > 32768:raise ValueError('package-limit')
    return {'company-install.sh':entry,'company_install.py':worker}

def emit(root, destination, fingerprint, *, host_catalogs=None):
    if os.name != 'posix' or os.geteuid() != 0 or os.getegid() != 0 or UNRELEASED:
        raise ValueError('company-linux-root-producer-required')
    records=assemble(root,fingerprint,host_catalogs=host_catalogs);destination=Path(destination)
    if not destination.is_absolute():raise ValueError('absolute-package-output-required')
    for parent in destination.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode)&0o022:
            raise ValueError('package-output-ancestry')
    parent_fd=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    opened=os.fstat(parent_fd)
    try:
        destination.mkdir(mode=0o700) # Never adopt an existing output/package.
        for name,raw in records.items():
            fd=os.open(destination/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o400)
            try:
                offset=0
                while offset < len(raw):
                    count=os.write(fd,raw[offset:offset+65536])
                    if type(count) is not int or count <= 0:raise ValueError('package-short-write')
                    offset+=count
                os.fsync(fd)
            finally:
                try:os.close(fd)
                except BaseException:UNRELEASED.append(fd);raise
            if protected_read(destination/name,524288 if name=='company_install.py' else 32768) != raw:raise ValueError('package-readback')
        directory_fd=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory_fd)
        finally:
            try:os.close(directory_fd)
            except BaseException:UNRELEASED.append(directory_fd);raise
        os.fsync(parent_fd)
        if any(getattr(opened,key) != getattr(os.fstat(parent_fd),key) or getattr(opened,key) != getattr(destination.parent.lstat(),key) for key in FIELDS[:5]):
            raise ValueError('package-output-parent-replaced')
    finally:
        try:os.close(parent_fd)
        except BaseException:UNRELEASED.append(parent_fd);raise
    return {name:dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw)) for name,raw in records.items()}

def read_catalogs(root,paths,*,reader=protected_read):
    if not paths:return None
    if set(paths) not in ({'tools','packages'},{'engine'}):raise ValueError('one-independent-host-catalog-family-required')
    source=Path(root).resolve(strict=True);result={}
    for name,(filename,expected) in paths.items():
        p=Path(filename)
        if not p.is_absolute() or p.resolve(strict=True)!=p or p.is_relative_to(source):raise ValueError('independent-protected-host-catalog-required')
        if type(expected) is not str or re.fullmatch('[a-f0-9]{64}',expected) is None:raise ValueError('independent-host-catalog-digest-required')
        raw=reader(p,{'tools':16384,'packages':32768,'engine':65536}[name])
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('host-catalog-digest-mismatch')
        result[name]=raw
    return result


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);p.add_argument('destination',type=Path);p.add_argument('--fingerprint',required=True)
    p.add_argument('--host-tool-catalog',type=Path);p.add_argument('--host-tool-catalog-sha256')
    p.add_argument('--host-package-catalog',type=Path);p.add_argument('--host-package-catalog-sha256')
    p.add_argument('--engine-catalog',type=Path);p.add_argument('--engine-catalog-sha256')
    a=p.parse_args();values=(a.host_tool_catalog,a.host_tool_catalog_sha256,a.host_package_catalog,a.host_package_catalog_sha256)
    if any(value is not None for value in values) and not all(value is not None for value in values):raise ValueError('both-independent-host-catalogs-and-digests-required')
    if (a.engine_catalog is None)!=(a.engine_catalog_sha256 is None):raise ValueError('independent-engine-catalog-and-digest-required')
    if a.engine_catalog is not None and any(value is not None for value in values):raise ValueError('mixed-vendor-and-company-catalogs-refused')
    catalogs=read_catalogs(a.root,{'tools':(a.host_tool_catalog,a.host_tool_catalog_sha256),'packages':(a.host_package_catalog,a.host_package_catalog_sha256)}) if all(value is not None for value in values) else None
    if a.engine_catalog is not None:catalogs=read_catalogs(a.root,{'engine':(a.engine_catalog,a.engine_catalog_sha256)})
    print(json.dumps(emit(a.root,a.destination,a.fingerprint,host_catalogs=catalogs),sort_keys=True))

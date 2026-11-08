"""Bind exact company-approved host packages before the foundation invokes a manager.

Company-authenticated delivery must supply the expected catalog digest and the
matching host-tool binding. Package provenance and qualification are producer
responsibilities. This module neither downloads packages nor grants authority.
"""
from contextlib import ExitStack,contextmanager
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import stat
from types import MappingProxyType

NAMES=('docker-ce','docker-ce-cli','containerd.io','docker-buildx-plugin','docker-compose-plugin')
KEYS={'debian':'9DC858229FC7DD38854AE2D88D81803C0EBFCD88',
      'rocky':'060A61C51B558A7F742B77AAC52FEB6B621E9F35'}
MAX_CATALOG=32768
PREFIX='/opt/autosoft-company/host-packages/'

def require(value,reason='Approved host package set is unavailable; preserve the installation for IT review'):
    if not value:raise ValueError(reason)

def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value) and value!='0'*64)
    return value
def pairs(rows):
    result={}
    for key,value in rows:require(key not in result);result[key]=value
    return result

def decode(raw,expected_sha256,profiles):
    require(type(raw) is bytes and 0<len(raw)<=MAX_CATALOG and sha(raw)==digest(expected_sha256))
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False))
    require(type(value) is dict and set(value)=={'schemaVersion','scope','profiles'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='COMPANY_HOST_PACKAGE_CATALOG' and canonical(value)==raw)
    require(type(value['profiles']) is list and 1<=len(value['profiles'])<=16)
    order=[]
    for row in value['profiles']:
        require(type(row) is dict and set(row)=={'platform','toolProfileSha256','qualificationReportSha256','vendorKey','packages'})
        identity=profiles.platform(row['platform']);require(identity not in order);order.append(identity)
        digest(row['toolProfileSha256']);digest(row['qualificationReportSha256'])
        key=row['vendorKey'];require(type(key) is dict and set(key)=={'filename','bytes','sha256','fingerprint'})
        require(key['filename']=='docker.asc' and type(key['bytes']) is int and 1024<=key['bytes']<=65536
            and key['fingerprint']==KEYS[row['platform']['osId']]);digest(key['sha256'])
        rows=row['packages'];require(type(rows) is list and len(rows)==len(NAMES))
        require(all(type(item) is dict for item in rows) and [item.get('name') for item in rows]==list(NAMES))
        suffix='deb' if identity[0]=='debian' else 'rpm'
        architecture='amd64' if identity[0]=='debian' else 'x86_64'
        for item in rows:
            require(set(item)=={'name','version','architecture','filename','bytes','sha256','repositoryMetadataSha256'})
            require(item['filename']==item['name']+'.'+suffix and item['architecture']==architecture
                and type(item['version']) is str and re.fullmatch('[A-Za-z0-9.+:~_-]{1,128}',item['version'])
                and type(item['bytes']) is int and 16384<=item['bytes']<=256*1024**2)
            require(identity[0]!='rocky' or not item['version'].startswith('0:'), 'RPM catalog versions must omit a zero epoch')
            digest(item['sha256']);digest(item['repositoryMetadataSha256'])
        require(sum(item['bytes'] for item in rows)<=1024**3)
    require(order==sorted(order))
    return value

def bind(raw,*,expected_catalog_sha256,observed_platform,host_tools,profiles):
    catalog=decode(raw,expected_catalog_sha256,profiles)
    wanted=profiles.platform(observed_platform)
    selected=[row for row in catalog['profiles'] if profiles.platform(row['platform'])==wanted]
    require(len(selected)==1);row=selected[0]
    require(type(host_tools) is MappingProxyType and host_tools['scope']=='COMPANY_HOST_TOOL_PROFILE_BINDING_ONLY')
    require(dict(host_tools['platform'])==observed_platform and host_tools['profileSha256']==row['toolProfileSha256']
        and host_tools['qualificationReportSha256']==row['qualificationReportSha256'])
    packages={item['name']:item for item in row['packages']}
    for name in ('docker','compose'):
        tool=host_tools['tools'][name]['package'];package=packages[tool['name']]
        require(all(package[key]==tool[key] for key in ('name','version','architecture','repositoryMetadataSha256'))
            and package['sha256']==tool['archiveSha256'])
    root=PREFIX+expected_catalog_sha256
    artifacts=[dict(item,path=root+'/'+item['filename']) for item in row['packages']]
    key=dict(row['vendorKey'],path=root+'/docker.asc')
    arguments=tuple(value for item in artifacts+[key] for value in (item['path'],item['sha256']))
    return MappingProxyType(dict(scope='COMPANY_HOST_PACKAGE_BINDING_ONLY',catalogSha256=expected_catalog_sha256,
        profileSha256=sha(canonical(row)),toolProfileSha256=row['toolProfileSha256'],
        qualificationReportSha256=row['qualificationReportSha256'],platform=MappingProxyType(dict(observed_platform)),
        root=root,artifacts=tuple(MappingProxyType(item) for item in artifacts+[key]),
        shellArguments=arguments,packagesInstalled=False,parentAuthorityEstablished=False))

@contextmanager
def held_archives(binding,station,*,check_authority):
    """Hold all package bytes and protected ancestors through the package phase.

    station is the original captured native station, supplied by the fixed
    worker. Tests may supply a mapped reader; administrator input cannot.
    """
    require(type(binding) is MappingProxyType and binding['scope']=='COMPANY_HOST_PACKAGE_BINDING_ONLY')
    require(type(binding['artifacts']) is tuple and len(binding['artifacts'])==6)
    checks=[]
    with ExitStack() as stack:
        for item in binding['artifacts']:
            check_authority()
            path=PurePosixPath(item['path'])
            require(str(path.parent)==binding['root'] and str(path)==item['path'])
            fd,info,check=stack.enter_context(station.held_file(str(path),item['bytes']))
            require(info['st_size']==item['bytes'] and stat.S_IMODE(info['st_mode'])==0o400)
            digest=hashlib.sha256();offset=0
            while offset<item['bytes']:
                check_authority();check()
                raw=os.pread(fd,min(1024**2,item['bytes']-offset),offset);require(raw)
                offset+=len(raw);digest.update(raw)
            require(not os.pread(fd,1,offset) and digest.hexdigest()==item['sha256'])
            check();checks.append(check)
        def recheck():
            check_authority()
            for check in checks:check()
        recheck();yield binding['shellArguments'],recheck;recheck()
    check_authority()

def append_phase_arguments(command,arguments):
    """Fixed caller seam; only the packages phase receives the twelve additions."""
    require(type(command) is list and len(command)==13 and command[:4]==['/bin/bash','--noprofile','--norc','-c']
        and command[5]=='company-foundation' and command[4].endswith('\ncompany_packages_phase "$@"\n'))
    require(type(arguments) is tuple and len(arguments)==12)
    require(all(type(value) is str for value in arguments))
    match=re.fullmatch(re.escape(PREFIX)+r'([a-f0-9]{64})/docker-ce\.(deb|rpm)',arguments[0])
    require(match is not None)
    root=PREFIX+match.group(1);suffix=match.group(2)
    names=[name+'.'+suffix for name in NAMES]+['docker.asc']
    for index,name in enumerate(names):
        require(arguments[index*2]==root+'/'+name);digest(arguments[index*2+1])
    return command+list(arguments)

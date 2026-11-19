"""Decode company-delivered host tool identities; never infer trust from a host.

The expected catalog hash must be embedded in the independently authenticated
company worker. A request, installed binary, or this catalog's own hash cannot
supply that authority. The producer separately verifies vendor signatures and
qualification evidence before approving a catalog. No production profile or
installation/download/approval capability is provided by this module.
"""
import hashlib
import json
import re
from types import MappingProxyType

MAX_BYTES=16384
PATHS={
    'docker':('/usr/bin/docker',),
    'compose':('/usr/libexec/docker/cli-plugins/docker-compose',
               '/usr/lib/docker/cli-plugins/docker-compose',
               '/usr/local/lib/docker/cli-plugins/docker-compose'),
}
PACKAGES={'docker':'docker-ce-cli','compose':'docker-compose-plugin'}

def require(value):
    if not value:
        raise ValueError('No matching authenticated host-tool profile; preserve the installation for IT review')

def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')

def digest(raw):return hashlib.sha256(raw).hexdigest()

def pin(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}',value) and value!='0'*64)
    return value

def pairs(items):
    result={}
    for key,value in items:
        require(key not in result);result[key]=value
    return result

def platform(value):
    require(type(value) is dict and set(value)=={'osId','versionId','architecture'})
    require(value['osId'] in ('debian','rocky') and value['architecture']=='x86_64')
    require(type(value['versionId']) is str and re.fullmatch(r'[0-9]{1,2}(?:\.[0-9]{1,2})?',value['versionId']))
    major=value['versionId'].split('.')[0]
    require(major in (('12','13') if value['osId']=='debian' else ('9','10')))
    return value['osId'],value['versionId'],value['architecture']

def decode(raw,*,expected_catalog_sha256):
    require(type(raw) is bytes and 0<len(raw)<=MAX_BYTES)
    require(digest(raw)==pin(expected_catalog_sha256))
    try:
        value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:require(False))
        require(canonical(value)==raw)
    except (UnicodeError,TypeError,RecursionError):
        raise ValueError('Host-tool catalog is malformed') from None
    require(type(value) is dict and set(value)=={'schemaVersion','scope','profiles'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='COMPANY_HOST_TOOL_PROFILES')
    require(type(value['profiles']) is list and 1<=len(value['profiles'])<=16)
    seen=set()
    for row in value['profiles']:
        require(type(row) is dict and set(row)=={'platform','tools','qualificationReportSha256'})
        key=platform(row['platform']);require(key not in seen);seen.add(key)
        pin(row['qualificationReportSha256'])
        require(type(row['tools']) is dict and set(row['tools'])==set(PATHS))
        for name,tool in row['tools'].items():
            require(type(tool) is dict and set(tool)=={'path','bytes','sha256','package'})
            require(tool['path'] in PATHS[name] and type(tool['bytes']) is int and 64<=tool['bytes']<=256*1024**2)
            pin(tool['sha256'])
            package=tool['package']
            require(type(package) is dict and set(package)=={'name','version','architecture','archiveSha256','repositoryMetadataSha256'})
            require(package['name']==PACKAGES[name] and type(package['version']) is str
                and re.fullmatch('[A-Za-z0-9.+:~_-]{1,128}',package['version']))
            require(package['architecture']==('amd64' if row['platform']['osId']=='debian' else 'x86_64'))
            pin(package['archiveSha256']);pin(package['repositoryMetadataSha256'])
    # Canonical sorted profile order gives one representation for a catalog.
    require([platform(row['platform']) for row in value['profiles']]==sorted(seen))
    return value

def bind(raw,*,expected_catalog_sha256,observed_platform):
    """Select exact company data for separately verified host OS/architecture.

    observed_platform comes from the existing trusted host inspection, never
    administrator request fields. Point releases are not guessed compatible.
    Output intentionally makes no claim that a tool is installed or qualified.
    """
    wanted=platform(observed_platform)
    catalog=decode(raw,expected_catalog_sha256=expected_catalog_sha256)
    selected=[row for row in catalog['profiles'] if platform(row['platform'])==wanted]
    require(len(selected)==1)
    row=selected[0]
    return MappingProxyType(dict(
        scope='COMPANY_HOST_TOOL_PROFILE_BINDING_ONLY',catalogSha256=expected_catalog_sha256,
        profileSha256=digest(canonical(row)),platform=MappingProxyType(dict(row['platform'])),
        qualificationReportSha256=row['qualificationReportSha256'],
        tools=MappingProxyType({name:MappingProxyType(dict(path=tool['path'],bytes=tool['bytes'],sha256=tool['sha256'],
            package=MappingProxyType(dict(tool['package'])))) for name,tool in row['tools'].items()}),
        installedToolsVerified=False,qualificationEvidenceVerified=False,parentAuthorityEstablished=False,
    ))

def transport_pins(binding):
    """Copy only finite tool identities into the separately checked transport.

    The original worker retains catalogSha256/profileSha256 in its stage binding.
    This projection is neither a catalog authenticator nor a tool installer.
    """
    require(type(binding) is MappingProxyType and binding.get('scope')=='COMPANY_HOST_TOOL_PROFILE_BINDING_ONLY')
    require(type(binding.get('tools')) is MappingProxyType and set(binding['tools'])==set(PATHS))
    return {name:{key:tool[key] for key in ('path','bytes','sha256')} for name,tool in binding['tools'].items()}

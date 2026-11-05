#!/usr/bin/env python3
"""Check explicitly reviewed public dependencies without uploading a private tree.

Only the exact npm Bulk Advisory endpoint is used. No npm CLI, npmrc, auth,
proxy configuration, quick-audit fallback, installation or remediation executes.
This covers public dependency advisories, not full release security acceptance.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import urllib.request
from urllib.parse import urlsplit, unquote

ENDPOINT='https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
NAME=re.compile(r'(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z')
VERSION=re.compile(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z')


def payload(lock, reviewed):
    if (not isinstance(reviewed,dict) or reviewed.get('schemaVersion') not in (1,2) or
            set(reviewed)!=({'schemaVersion','publicPackages'} if reviewed.get('schemaVersion')==1 else {'schemaVersion','publicPackages','localWorkspaces'}) or
            not isinstance(reviewed['publicPackages'],list) or
            any(not isinstance(n,str) or not NAME.fullmatch(n) for n in reviewed['publicPackages']) or
            len(set(reviewed['publicPackages']))!=len(reviewed['publicPackages'])):
        raise ValueError('Exact company-reviewed public-package catalog required')
    if not isinstance(lock,dict) or lock.get('lockfileVersion')!=3 or not isinstance(lock.get('packages'),dict):
        raise ValueError('Supported complete dependency lock required')
    workspaces={}
    rows=reviewed.get('localWorkspaces',[])
    if not isinstance(rows,list) or len(rows)>128: raise ValueError('Bounded reviewed local workspaces required')
    for row in rows:
        if (not isinstance(row,dict) or set(row)!={'path','name'} or not isinstance(row['path'],str) or
                not re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9._-]+)+',row['path']) or
                any(part in ('.','..','node_modules','.git') for part in row['path'].split('/')) or
                not isinstance(row['name'],str) or not NAME.fullmatch(row['name']) or
                row['path'] in workspaces or row['name'] in workspaces.values()):
            raise ValueError('Exact unique company-reviewed workspace identities required')
        workspaces[row['path']]=row['name']
    for path,name in workspaces.items():
        row=lock['packages'].get(path)
        link=lock['packages'].get('node_modules/'+name)
        if (not isinstance(row,dict) or row.get('name')!=name or not isinstance(row.get('version'),str) or
                not VERSION.fullmatch(row['version']) or any(k in row for k in ('resolved','integrity','link')) or
                not isinstance(link,dict) or link.get('link') is not True or link.get('resolved')!=path):
            raise ValueError('Reviewed local workspace and its exact link must both exist')
    allowed=set(reviewed['publicPackages']); result={}; excluded=0
    for path,row in lock['packages'].items():
        if not isinstance(path,str) or not isinstance(row,dict): raise ValueError('Malformed lock entry')
        if not path:
            excluded+=1; continue
        if path in workspaces:
            excluded+=1; continue
        if row.get('link') is True:
            target=row.get('resolved')
            if not isinstance(target,str) or workspaces.get(target) is None or path!='node_modules/'+workspaces[target]:
                raise ValueError('Unreviewed workspace link; no request sent')
            excluded+=1; continue
        if row.get('private') is True:
            raise ValueError('Private external dependency needs separate coverage; public scan cannot pass')
        if 'node_modules/' not in path or '\\' in path or '..' in path.split('/'):
            raise ValueError('Unrecognized dependency placement; no request sent')
        name=path.rsplit('node_modules/',1)[1]
        version=row.get('version'); resolved=row.get('resolved')
        if name not in allowed or not NAME.fullmatch(name) or not isinstance(version,str) or not VERSION.fullmatch(version) or not isinstance(resolved,str):
            raise ValueError('Unreviewed or unversioned public dependency; no request sent')
        url=urlsplit(resolved)
        expected='/'+name+'/-/'+name.rsplit('/',1)[-1]+'-'+version+'.tgz'
        if (url.scheme!='https' or url.netloc!='registry.npmjs.org' or url.username or url.password or url.query or url.fragment or
                unquote(url.path)!=expected):
            raise ValueError('Dependency provenance is not the exact reviewed public registry package')
        integrity=row.get('integrity')
        if not isinstance(integrity,str) or not re.fullmatch(r'sha512-[A-Za-z0-9+/]{86}==',integrity):
            raise ValueError('Pinned SHA512 dependency integrity required')
        result.setdefault(name,set()).add(version)
    if not result or len(result)>1000: raise ValueError('Bounded nonempty public dependency inventory required')
    return {name:sorted(versions) for name,versions in sorted(result.items())},excluded


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        raise ValueError('Advisory endpoint redirect refused')


def query(public_payload, opener=None):
    body=json.dumps(public_payload,sort_keys=True,separators=(',',':')).encode()
    if len(body)>256*1024: raise ValueError('Advisory request exceeds bound')
    request=urllib.request.Request(ENDPOINT,data=body,method='POST',headers={'Content-Type':'application/json','Accept-Encoding':'identity','Accept':'application/json'})
    client=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with client.open(request,timeout=30) as response:
        if response.status!=200 or response.geturl()!=ENDPOINT or response.headers.get('Content-Encoding','identity')!='identity':
            raise ValueError('Advisory response unavailable')
        declared=response.headers.get('Content-Length')
        if declared is not None and (not re.fullmatch(r'\d{1,9}',declared) or int(declared)>8*1024*1024):
            raise ValueError('Advisory response exceeds bound')
        raw=response.read(8*1024*1024+1)
        if len(raw)>8*1024*1024 or declared is not None and len(raw)!=int(declared): raise ValueError('Incomplete bounded advisory response')
    value=json.loads(raw)
    if not isinstance(value,dict) or any(name not in public_payload for name in value): raise ValueError('Unexpected advisory scope')
    findings=[]; low=0
    for name,advisories in value.items():
        if not isinstance(advisories,list) or len(advisories)>1000: raise ValueError('Malformed advisory collection')
        for item in advisories:
            # npm groups bulk results by package; its CLI passes that outer name
            # to the advisory calculator. Current registry responses may omit
            # item.name. Never accept a conflicting explicit inner identity.
            if not isinstance(item,dict) or ('name' in item and item['name']!=name) or item.get('severity') not in ['low','moderate','high','critical']:
                raise ValueError('Unclassified advisory; scan cannot pass')
            for key in ['id','url','title','vulnerable_versions']:
                if key not in item or not isinstance(item[key],(str,int)) or isinstance(item[key],bool) or len(str(item[key]))>4000:
                    raise ValueError('Incomplete advisory')
            url=urlsplit(str(item['url']))
            if url.scheme!='https' or not url.hostname or url.username or url.password or any(c in str(item['url']) for c in '\r\n'):
                raise ValueError('Invalid advisory evidence URL')
            if item['severity']=='low': low+=1; continue
            finding={key:item[key] for key in ['id','url','title','vulnerable_versions']}
            finding['name']=name
            finding.update(severity='medium' if item['severity']=='moderate' else item['severity'],sourceSeverity=item['severity'])
            findings.append(finding)
    return dict(status='blocked' if findings else 'no_medium_or_higher_advisories_returned',findings=findings,lowAdvisoriesIgnored=low,
                payloadSha256=hashlib.sha256(body).hexdigest(),responseSha256=hashlib.sha256(raw).hexdigest())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock',required=True); parser.add_argument('--reviewed-public-packages',required=True)
    parser.add_argument('--dry-run',action='store_true'); parser.add_argument('--report')
    args=parser.parse_args()
    lock_raw=Path(args.lock).read_bytes(); catalog_raw=Path(args.reviewed_public_packages).read_bytes()
    if len(lock_raw)>4*1024*1024 or len(catalog_raw)>256*1024: raise ValueError('Input bounds exceeded')
    selected,excluded=payload(json.loads(lock_raw),json.loads(catalog_raw))
    report=dict(schemaVersion=1,checkedAt=datetime.now(timezone.utc).isoformat(),lockSha256=hashlib.sha256(lock_raw).hexdigest(),
                publicCatalogSha256=hashlib.sha256(catalog_raw).hexdigest(),publicPackageCount=len(selected),
                excludedRootOrWorkspaceCount=excluded,privatePackageNamesSent=False,fullDependencyTreeSent=False,
                quickAuditFallback=False,packagesChanged=False,coverage='Reviewed public dependency advisories only; source, private code, OS and image scans remain separate.')
    if args.dry_run: report.update(status='dry_run',networkRequests=0,payload=selected)
    else: report.update(query(selected),networkRequests=1)
    encoded=json.dumps(report,indent=2)+'\n'
    if args.report: Path(args.report).write_text(encoded,encoding='utf-8')
    print(encoded)
    return 1 if report['status']=='blocked' else 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception:
        print(json.dumps(dict(status='unavailable',error='Public dependency advisory check stopped; no scan pass or remediation granted.')))
        raise SystemExit(2)

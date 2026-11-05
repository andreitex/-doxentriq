#!/usr/bin/env python3
"""Verify pushed single-platform content using the target registry's TLS API."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

DIGEST=re.compile(r'^sha256:[a-f0-9]{64}$')
MEDIA={'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
DOCKER_INSPECTION_SOURCE='https://github.com/moby/moby/blob/master/daemon/containerd/image_inspect.go'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_args,**_kwargs):
        raise ValueError('Registry manifest qualification does not follow redirects')

def credentials(host):
    path=Path(os.environ.get('DOCKER_CONFIG',str(Path.home()/'.docker')))/'config.json'
    if not path.exists(): return None
    if path.is_symlink() or not path.is_file() or os.name!='nt' and path.stat().st_mode&0o077:
        raise ValueError('Protected Docker credential file required')
    value=json.loads(path.read_text())
    entry=value.get('auths',{}).get(host) or value.get('auths',{}).get('https://'+host)
    if not entry:
        if value.get('credsStore') or value.get('credHelpers',{}).get(host):
            raise ValueError('Company registry qualification requires an isolated inline Docker credential file; credential helper execution is unsupported')
        return None
    auth=entry.get('auth')
    if not isinstance(auth,str): raise ValueError('Company registry Docker basic credentials unavailable')
    decoded=base64.b64decode(auth,validate=True)
    if b':' not in decoded or b'\r' in decoded or b'\n' in decoded or len(decoded)>8192:
        raise ValueError('Invalid protected registry credentials')
    return 'Basic '+base64.b64encode(decoded).decode()

class Registry:
    def __init__(self,host,repository):
        self.host,self.repository=host,repository
        context=ssl.create_default_context()
        ca=Path('/etc/docker/certs.d')/host/'ca.crt'
        if ca.exists():
            if ca.is_symlink() or not ca.is_file() or ca.stat().st_mode&0o022:
                raise ValueError('Protected Docker registry CA required')
            context.load_verify_locations(cafile=str(ca))
        self.opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),NoRedirect())
        self.authorization=credentials(host)

    def request(self,path,method='GET',limit=2<<20):
        url='https://'+self.host+path
        headers={'Accept':','.join(sorted(MEDIA))}
        if self.authorization:headers['Authorization']=self.authorization
        request=urllib.request.Request(url,headers=headers,method=method)
        try:
            response=self.opener.open(request,timeout=30)
        except urllib.error.HTTPError as error:
            challenge=error.headers.get('WWW-Authenticate','')
            if error.code!=401 or not challenge.startswith('Bearer '):
                raise ValueError('Target registry request failed HTTP '+str(error.code)) from None
            fields=dict(re.findall(r'([a-z]+)="([^"\r\n]*)"',challenge))
            realm=urllib.parse.urlsplit(fields.get('realm',''))
            if realm.scheme!='https' or realm.netloc!=self.host or realm.username or realm.password or realm.fragment:
                raise ValueError('Registry Bearer authentication must remain on its verified HTTPS authority')
            query=urllib.parse.parse_qsl(realm.query,keep_blank_values=True)
            if any(key in {'service','scope'} for key,_ in query):raise ValueError('Ambiguous registry token scope')
            query += [('service',fields.get('service',self.host)),('scope','repository:'+self.repository+':pull')]
            token_url=urllib.parse.urlunsplit((realm.scheme,realm.netloc,realm.path,urllib.parse.urlencode(query),''))
            token_request=urllib.request.Request(token_url,headers={'Authorization':self.authorization} if self.authorization else {})
            try:
                with self.opener.open(token_request,timeout=30) as token_response:
                    if token_response.status!=200:raise ValueError('Registry scoped token request must return HTTP 200')
                    payload=token_response.read((1<<20)+1)
            except urllib.error.HTTPError as error:
                raise ValueError('Registry scoped token request failed HTTP '+str(error.code)) from None
            if len(payload)>1<<20:raise ValueError('Bounded registry token response exceeded')
            value=json.loads(payload);token=value.get('token') or value.get('access_token')
            if not isinstance(token,str) or not re.fullmatch(r'[^\s]{1,65536}',token):raise ValueError('Registry token unavailable')
            self.authorization='Bearer '+token
            request.add_header('Authorization',self.authorization)
            try:response=self.opener.open(request,timeout=30)
            except urllib.error.HTTPError as error:raise ValueError('Authenticated target registry request failed HTTP '+str(error.code)) from None
        with response:
            if response.status!=200:raise ValueError('Registry manifest/blob evidence must return HTTP 200')
            body=response.read(limit+1) if method!='HEAD' else b''
            if len(body)>limit:raise ValueError('Bounded registry content exceeded')
            return body,response.headers

def qualify(reference,local=None,client=None):
    match=re.fullmatch(r'([a-zA-Z0-9.-]+(?::[0-9]+)?)/([a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*):([a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127})',reference)
    if not match:raise ValueError('Exact company registry tag required')
    host,repository,tag=match.groups()
    if local is None:
        local=json.loads(subprocess.check_output(['docker','image','inspect','--platform','linux/amd64',reference],text=True))[0]
    if local.get('Os')!='linux' or local.get('Architecture')!='amd64' or not DIGEST.fullmatch(local.get('Id','')):
        raise ValueError('Only independently inspected Linux amd64 company content is supported')
    # The classic image store reports a config ID; the containerd image store
    # reports the selected target manifest ID. Never infer either from RepoDigests.
    source_descriptor=local.get('Descriptor')
    source_manifest=None
    if source_descriptor is not None:
        if not isinstance(source_descriptor,dict) or source_descriptor.get('mediaType') not in MEDIA or source_descriptor.get('digest')!=local['Id'] or type(source_descriptor.get('size')) is not int or not 0<source_descriptor['size']<=2<<20:
            raise ValueError('An independently inspected single-platform source manifest is required')
        platform=source_descriptor.get('platform')
        if platform is not None and (not isinstance(platform,dict) or platform.get('os')!='linux' or platform.get('architecture')!='amd64'):
            raise ValueError('Selected source descriptor platform differs')
        source_manifest=source_descriptor['digest']
    client=client or Registry(host,repository)
    body,headers=client.request('/v2/'+repository+'/manifests/'+tag)
    digest='sha256:'+hashlib.sha256(body).hexdigest()
    if headers.get('Docker-Content-Digest')!=digest:raise ValueError('Target manifest digest header differs from actual content')
    manifest=json.loads(body)
    if manifest.get('schemaVersion')!=2 or manifest.get('mediaType') not in MEDIA or headers.get('Content-Type','').split(';')[0] not in MEDIA:
        raise ValueError('A concrete single-platform target manifest is required')
    if source_manifest is not None and (source_manifest!=digest or source_descriptor['size']!=len(body)):
        raise ValueError('Target manifest bytes differ from the independently inspected source manifest')
    descriptor=manifest.get('config',{})
    expected_config=descriptor.get('digest') if source_manifest is not None else local['Id']
    annotations=source_descriptor.get('annotations',{}) if source_manifest is not None else {}
    if not isinstance(annotations,dict) or ('config.digest' in annotations and annotations['config.digest']!=expected_config):
        raise ValueError('Source config annotation differs from the manifest-bound config')
    if not isinstance(expected_config,str) or not DIGEST.fullmatch(expected_config) or descriptor.get('digest')!=expected_config or type(descriptor.get('size')) is not int or not 0<descriptor['size']<=2<<20:
        raise ValueError('Target config differs from independently inspected source image')
    config_body,config_headers=client.request('/v2/'+repository+'/blobs/'+descriptor['digest'])
    if len(config_body)!=descriptor['size'] or 'sha256:'+hashlib.sha256(config_body).hexdigest()!=expected_config or config_headers.get('Docker-Content-Digest')!=expected_config:
        raise ValueError('Target config blob integrity differs')
    config=json.loads(config_body)
    if config.get('architecture')!='amd64' or config.get('os')!='linux' or config.get('rootfs',{}).get('diff_ids')!=local.get('RootFS',{}).get('Layers'):
        raise ValueError('Target architecture or filesystem content differs')
    layers=manifest.get('layers')
    if not isinstance(layers,list) or not 1<=len(layers)<=128 or len(layers)!=len(config['rootfs']['diff_ids']):
        raise ValueError('Target layer inventory differs')
    for layer in layers:
        if not DIGEST.fullmatch(layer.get('digest','')) or type(layer.get('size')) is not int or not 0<layer['size']<=2<<30:
            raise ValueError('Invalid bounded target layer descriptor')
        _,blob_headers=client.request('/v2/'+repository+'/blobs/'+layer['digest'],'HEAD')
        if blob_headers.get('Docker-Content-Digest')!=layer['digest'] or blob_headers.get('Content-Length')!=str(layer['size']):
            raise ValueError('Target layer availability/integrity differs')
    return dict(reference=host+'/'+repository+'@'+digest,tag=reference,manifestDigest=digest,localDockerImageId=local['Id'],sourceIdentityMode='platform-manifest' if source_manifest is not None else 'legacy-config',sourceManifestDigest=source_manifest,sourceConfigId=expected_config,inspectionPlatform='linux/amd64',inspectionImplementation=DOCKER_INSPECTION_SOURCE,architecture='amd64',os='linux',filesystemDiffIds=config['rootfs']['diff_ids'],layerDescriptors=[dict(digest=layer['digest'],size=layer['size']) for layer in layers],verifiedTLS=True)

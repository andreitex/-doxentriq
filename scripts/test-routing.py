#!/usr/bin/env python3
"""Adapt reviewed public routing with the actual pinned Caddy, without serving it."""
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('Run this isolated validation as root')
    metadata = json.loads(Path('/etc/autosoft/installation.json').read_text())
    data = Path(metadata['data_dir'])
    if Path('/etc/autosoft/installation.complete').exists():
        raise SystemExit('Use an unaccepted company test foundation')
    source = Path(sys.argv[1]).resolve()
    image = sys.argv[2]
    proof = Path(sys.argv[3]) if len(sys.argv)>3 else Path(str(source)+'.manifest.json')
    manifest = json.loads(proof.read_text())
    files = {str(path.relative_to(source)):hashlib.sha256(path.read_bytes()).hexdigest() for path in source.rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc'}
    if files != manifest['files']:
        raise SystemExit('Routing test source differs from its verified per-file manifest')
    if not re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}', image):
        raise SystemExit('A pinned Caddy image is required')
    bootstrap_bytes = (source/'scripts/bootstrap.py').read_bytes()
    tree = ast.parse(bootstrap_bytes.decode('utf-8'))
    candidates = [node.args[1] for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'write' and len(node.args)>1 and isinstance(node.args[1], ast.JoinedStr) and any(isinstance(value, ast.Constant) and isinstance(value.value, str) and 'admin unix//run/caddy/admin.sock' in value.value for value in node.args[1].values)]
    if len(candidates) != 1:
        raise SystemExit('Expected one reviewed Caddy configuration expression')
    expression = candidates[0]
    allowed = (ast.JoinedStr, ast.Constant, ast.FormattedValue, ast.Name, ast.Load)
    if any(not isinstance(node, allowed) or (isinstance(node, ast.Name) and node.id not in {'admin_host','apps_host','auth_host'}) for node in ast.walk(expression)):
        raise SystemExit('Caddy expression contains an unexpected executable construct')
    hosts = dict(admin_host='admin.test.internal',apps_host='apps.test.internal',auth_host='identity.test.internal')
    caddyfile = eval(compile(ast.Expression(expression), '<reviewed routing>', 'eval'), {'__builtins__':{}}, hosts)
    with tempfile.TemporaryDirectory(prefix='routing-', dir=data/'validation') as folder:
        file = Path(folder)/'Caddyfile'
        file.write_text(caddyfile)
        os.chmod(folder, 0o755)
        os.chmod(file, 0o644)
        # The official Caddy binary carries cap_net_bind_service=ep; mirror its
        # one production capability even though adaptation binds no sockets.
        adapted = json.loads(subprocess.check_output(['docker','run','--rm','--runtime=runsc','--network=none','--read-only','--user=10001:10001','--cap-drop=ALL','--cap-add=NET_BIND_SERVICE','--security-opt=no-new-privileges','--memory=256m','--pids-limit=64','--env','HOME=/tmp','--tmpfs','/tmp:size=32m,mode=1777','--volume',str(file)+':/config/Caddyfile:ro,z',image,'caddy','adapt','--config','/config/Caddyfile'], text=True))
    servers = adapted['apps']['http']['servers']
    assert len(servers) == 1
    routes = next(iter(servers.values()))['routes']
    portal = next(route for route in routes if any(match.get('host')==[hosts['apps_host']] for match in route.get('match',[])))
    wildcard = next(route for route in routes if any(match.get('host')==['*.'+hosts['apps_host']] for match in route.get('match',[])))
    public_routes = [item for item in walk(portal) if item.get('match') and any('method' in match for match in item['match'])]
    assert len(public_routes) == 2
    assert {json.dumps(route['match'],sort_keys=True) for route in public_routes} == {
        json.dumps([dict(method=['GET'],path=['/','/invite','/api/public/v1/apps','/portal-assets/*'])],sort_keys=True),
        json.dumps([dict(method=['POST'],path=['/api/public/v1/invitations/inspect','/api/public/v1/invitations/accept'])],sort_keys=True),
    }
    proxies = [item for item in walk(portal) if item.get('handler')=='reverse_proxy']
    assert len(proxies) == 2
    for proxy in proxies:
        assert proxy['upstreams']==[dict(dial='control:3000')]
        request_headers = proxy['headers']['request']
        assert set(request_headers['delete']) == {'Authorization','Cookie'}
        assert request_headers['set']['Host']==['{http.request.host}']
        assert 'tls' in proxy['transport']
    assert not any(item.get('handler')=='reverse_proxy' for item in walk(wildcard))
    assert any(item.get('handler')=='static_response' and item.get('status_code')==404 for item in walk(wildcard))
    report = dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='passed',scope='Actual Caddy adaptation and public routing boundaries',source=str(source),bootstrapSourceSha256=hashlib.sha256(bootstrap_bytes).hexdigest(),adaptedInputSha256=hashlib.sha256(caddyfile.encode()).hexdigest(),testConfiguration=True,platformDeployed=False,caddyImage=image,checks=['Pinned Caddy adapts the reviewed installer configuration offline in gVisor','Exact apps host allows only GET public portal/catalog/assets and POST invitation inspect/accept','Portal upstream verifies control TLS and preserves Host','Incoming Cookie and Authorization are removed','Unpublished wildcard hosts have only a 404 response'],limitations=['This check adapts configuration; full live public HTTPS, browser and app publication tests remain required'],modelApiCalls=0)
    report['sourceSnapshot']=dict(sourceManifestPath=str(proof),sourceManifestSha256=hashlib.sha256(proof.read_bytes()).hexdigest(),archiveSha256=manifest['archiveSha256'],fileManifestSha256=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),fileCount=len(files))
    report['testRunner']=dict(path=str(Path(__file__)),sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (data/'validation/routing-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

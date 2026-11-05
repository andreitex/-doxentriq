#!/usr/bin/env python3
"""Isolated real Keycloak/PKCE recovery proof, never a platform acceptance.

Root on the explicitly authorized, unaccepted encrypted company test VM only.
No upstream SSO, provider calls, shared service mounts, or credential output.
"""
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookies import SimpleCookie
import base64
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import uuid

IMAGE = 'quay.io/keycloak/keycloak@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc'
NODE_IMAGE = 'node@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20'


def run(args, **kwargs):
    return subprocess.run([str(item) for item in args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def out(args): return run(args).stdout.decode().strip()


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def write(path, value, uid=0):
    path.write_text(json.dumps(value) if isinstance(value, (dict, list)) else value)
    os.chmod(path, 0o600)
    os.chown(path, uid, uid)


def b64(value): return base64.urlsafe_b64encode(value).decode().rstrip('=')


def un64(value): return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def remaining_codes(credential):
    data = json.loads(credential['credentialData'])
    values = [data[name] for name in ('remaining', 'remainingCodes') if name in data]
    if not values or any(type(value) is not int or value != values[0] for value in values): raise ValueError('Recovery metadata contract differs: ' + ','.join(sorted(data)))
    return values[0]


class Forms(HTMLParser):
    def __init__(self, raw):
        super().__init__()
        self.forms, self.form, self.button, self.textarea, self.selection_form = [], None, None, None, None
        self.feed(raw)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form':
            self.form = dict(id=values.get('id', ''), action=values.get('action', ''), fields={}, buttons=[], text='')
            self.forms.append(self.form)
            if values.get('id') == 'kc-select-credential-form': self.selection_form = self.form
        elif self.form and tag == 'input' and values.get('name'):
            if values.get('type') not in ('submit', 'checkbox', 'radio'):
                self.form['fields'][values['name']] = values.get('value', '')
        elif self.form and tag == 'button':
            self.button = dict(name=values.get('name'), value=values.get('value', ''), text='')
            self.form['buttons'].append(self.button)
        elif self.form and tag == 'textarea' and values.get('name'):
            self.textarea = values['name']
            self.form['fields'][self.textarea] = ''

    def handle_data(self, text):
        if self.form: self.form['text'] += text
        elif self.selection_form: self.selection_form['text'] += text
        if self.button: self.button['text'] += text
        if self.form and self.textarea: self.form['fields'][self.textarea] += text

    def handle_endtag(self, tag):
        if tag == 'form': self.form = None
        elif tag == 'li': self.selection_form = None
        elif tag == 'button': self.button = None
        elif tag == 'textarea': self.textarea = None

    def choose(self, field=None, identifier=None):
        matches = [item for item in self.forms if (not field or field in item['fields']) and (not identifier or identifier == item['id'])]
        if len(matches) != 1: raise ValueError('Expected exact authentication form was unavailable')
        return matches[0]


def totp(secret):
    # Keycloak's hidden enrollment field is the raw secret; its displayed QR
    # uses TotpUtils.encode(raw). Do not decode the hidden field as base32.
    if not isinstance(secret, str) or not 16 <= len(secret) <= 128: raise ValueError('Unexpected OTP secret bounds')
    key = secret.encode('utf8')
    hashed = hmac.new(key, struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
    offset = hashed[-1] & 15
    return str((struct.unpack('>I', hashed[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def der(tag, value):
    length = len(value)
    encoded = bytes([length]) if length < 128 else bytes([128 + (length.bit_length() + 7) // 8]) + length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + encoded + value


def rsa_public(jwk):
    def integer(value):
        raw = un64(value)
        if not raw or len(raw) > 1024: raise ValueError('Invalid signing key bounds')
        if raw[0] & 128: raw = b'\0' + raw
        return der(2, raw)
    if len(un64(jwk['n'])) < 256: raise ValueError('Signing key strength is inadequate')
    rsa = der(0x30, integer(jwk['n']) + integer(jwk['e']))
    return der(0x30, bytes.fromhex('300d06092a864886f70d0101010500') + der(3, b'\0' + rsa))


class Browser:
    def __init__(self, request, origin, client_secret, callback, work):
        self.request, self.origin, self.secret, self.callback, self.work = request, origin, client_secret, callback, work
        self.cookies = SimpleCookie()
        self.state, self.nonce, self.verifier = [secrets.token_urlsafe(40) for _ in range(3)]
        self.location, self.raw = None, ''

    def visit(self, url, fields=None):
        target = urllib.parse.urlsplit(urllib.parse.urljoin(self.origin, url))
        if target.scheme != 'https' or target.netloc != urllib.parse.urlsplit(self.origin).netloc:
            raise ValueError('Unexpected authentication destination')
        headers = {'Cookie': '; '.join(name + '=' + morsel.value for name, morsel in self.cookies.items())}
        status, values, body = self.request(target.path + ('?' + target.query if target.query else ''), method='POST' if fields is not None else 'GET', value=fields, form=fields is not None, headers=headers)
        for name, value in values:
            if name.lower() == 'set-cookie': self.cookies.load(value)
        if status in (302, 303):
            self.location = dict((name.lower(), value) for name, value in values).get('location')
            next_url = urllib.parse.urlsplit(self.location or '')
            callback = urllib.parse.urlsplit(self.callback)
            if (next_url.scheme, next_url.netloc, next_url.path) == (callback.scheme, callback.netloc, callback.path):
                self.raw = ''
                return
            return self.visit(self.location)
        if status != 200: raise ValueError('Authentication returned an unexpected HTTP status')
        self.location, self.raw = None, body.decode()

    def start(self):
        self.visit('/realms/platform/protocol/openid-connect/auth?' + urllib.parse.urlencode(dict(client_id='autosoft-admin', response_type='code', redirect_uri=self.callback, scope='openid profile', state=self.state, nonce=self.nonce, code_challenge=b64(hashlib.sha256(self.verifier.encode()).digest()), code_challenge_method='S256', prompt='login')))

    def post(self, form, **fields):
        self.visit(form['action'], dict(form['fields'], **fields))

    def tokens(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.location or '').query)
        if query.get('state') != [self.state] or len(query.get('code', [])) != 1 or query.get('error'):
            raise ValueError('Authorization response state/code did not match')
        status, _, raw = self.request('/realms/platform/protocol/openid-connect/token', 'POST', dict(grant_type='authorization_code', client_id='autosoft-admin', client_secret=self.secret, redirect_uri=self.callback, code=query['code'][0], code_verifier=self.verifier), form=True)
        if status != 200: raise ValueError('PKCE token exchange failed')
        return json.loads(raw)

    def claims(self, token, jwks, owner, id_token=False):
        if not isinstance(token, str) or len(token) > 32000: raise ValueError('Token bounds exceeded')
        parts = token.split('.')
        if len(parts) != 3: raise ValueError('Malformed JWT')
        header = json.loads(un64(parts[0]))
        if header.get('alg') != 'RS256': raise ValueError('Unexpected JWT signature algorithm')
        keys = [key for key in jwks['keys'] if key.get('kid') == header.get('kid') and key.get('kty') == 'RSA' and key.get('use') == 'sig' and key.get('alg') == 'RS256']
        if len(keys) != 1: raise ValueError('Exact signing key unavailable')
        write(self.work / 'verify.pub.der', rsa_public(keys[0]).hex())
        (self.work / 'verify.pub.der').write_bytes(rsa_public(keys[0]))
        (self.work / 'verify.signature').write_bytes(un64(parts[2]))
        run(['openssl', 'dgst', '-sha256', '-keyform', 'DER', '-verify', self.work / 'verify.pub.der', '-signature', self.work / 'verify.signature'], input=(parts[0] + '.' + parts[1]).encode())
        claim = json.loads(un64(parts[1]))
        audience = claim.get('aud', [])
        if isinstance(audience, str): audience = [audience]
        if claim.get('iss') != self.origin + '/realms/platform' or claim.get('sub') != owner or 'autosoft-admin' not in audience or claim.get('exp', 0) <= time.time() or claim.get('iat', 0) > time.time() + 30 or claim.get('identity_provider'):
            raise ValueError('Exact local owner JWT identity validation failed')
        if id_token and claim.get('nonce') != self.nonce: raise ValueError('OIDC nonce mismatch')
        return claim


def main():
    if os.geteuid() != 0: raise SystemExit('Root is required for the isolated identity fixture')
    metadata = json.loads(Path('/etc/autosoft/installation.json').read_text())
    data = Path(metadata['data_dir'])
    if Path(out(['findmnt', '-n', '-o', 'SOURCE', '--target', data])).resolve() != Path('/dev/mapper/autosoft-data').resolve() or Path('/etc/autosoft/installation.complete').exists():
        raise SystemExit('Only an unaccepted encrypted test foundation may run this fixture')
    inspected = json.loads(out(['docker', 'image', 'inspect', IMAGE]))[0]
    if IMAGE not in inspected.get('RepoDigests', []): raise SystemExit('Exact previously verified Keycloak image is required')
    test_id, owner = uuid.uuid4().hex[:12], str(uuid.uuid4())
    work = data / 'validation' / ('identity-' + test_id)
    work.mkdir(mode=0o700)
    for directory in ('config', 'tls', 'public-tls', 'secrets/runtime', 'secrets/keycloak', 'keycloak-data/import'):
        (work / directory).mkdir(parents=True, exist_ok=True)
    for directory in ('keycloak-data', 'keycloak-data/import', 'secrets/keycloak'):
        os.chown(work / directory, 1000, 1000)
        os.chmod(work / directory, 0o700)
    bootstrap, identity = module('bootstrap'), module('identity')
    cfg = dict(certificate_mode='selfsigned', admin_origin='https://admin.test.internal', apps_base_url='https://apps.test.internal', auth_origin='https://identity.test.internal', sso='none', owner_subject=owner)
    bootstrap.certificates(work, cfg)
    temporary, password, client_secret, admin_secret = [secrets.token_urlsafe(40) for _ in range(4)]
    temporary = 'Aa1!' + temporary
    password = 'Aa1!' + password
    bootstrap.realm(work, cfg, client_secret, temporary, secrets.token_urlsafe(40))
    realm = json.loads((work / 'config/realm.json').read_text())
    if not any(flow.get('alias') == identity.RECOVERY_FLOW for flow in realm.get('authenticationFlows', [])):
        raise ValueError('Installer did not produce the qualified owner recovery flow')
    write(work / 'keycloak-data/import/platform-realm.json', realm, 1000)
    write(work / 'secrets/keycloak/master-password', admin_secret, 1000)
    write(work / 'config/start.sh', '#!/bin/bash\nset -eu\nexport KC_BOOTSTRAP_ADMIN_PASSWORD=$(cat /run/secrets/master-password)\nexec /opt/keycloak/bin/kc.sh start-dev --import-realm --db=dev-file\n')
    os.chmod(work / 'config/start.sh', 0o644)
    name, network = 'autosoft-identity-' + test_id, 'autosoft-identity-' + test_id
    container_id, checks, stage = None, [], 'isolated start'
    enrollment_forms = []
    selection_forms = []
    report_path = data / 'validation/identity-login-report.json'
    try:
        run(['chcon', '-R', '-t', 'container_file_t', work])
        run(['docker', 'network', 'create', '--internal', '--label', 'autosoft.identity.fixture=' + test_id, network])
        args = ['docker', 'run', '-d', '--pull=never', '--name', name, '--label', 'autosoft.identity.fixture=' + test_id, '--user', '1000:1000', '--network', network, '--network-alias', 'keycloak', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true', '--memory', '1536m', '--pids-limit', '256', '--entrypoint', '/bin/bash']
        for key, value in dict(KC_HOSTNAME=cfg['auth_origin'], KC_HOSTNAME_STRICT='true', KC_HTTP_ENABLED='false', KC_HTTPS_CERTIFICATE_FILE='/etc/autosoft/tls/keycloak.crt', KC_HTTPS_CERTIFICATE_KEY_FILE='/etc/autosoft/tls/keycloak.key', KC_BOOTSTRAP_ADMIN_USERNAME='bootstrap-admin').items(): args += ['--env', key + '=' + value]
        for source, target, readonly in [('keycloak-data', '/opt/keycloak/data', False), ('config/start.sh', '/fixture/start.sh', True), ('tls/keycloak', '/etc/autosoft/tls', True), ('secrets/keycloak', '/run/secrets', True)]:
            args += ['--mount', 'type=bind,source=' + str(work / source) + ',target=' + target + (',readonly' if readonly else '')]
        container_id = out(args + [IMAGE, '/fixture/start.sh'])
        info = json.loads(out(['docker', 'inspect', container_id]))[0]
        if info['Config']['Labels'].get('autosoft.identity.fixture') != test_id: raise ValueError('Fixture ownership mismatch')
        address = info['NetworkSettings']['Networks'][network]['IPAddress']
        tls = ssl.create_default_context(cafile=str(work / 'tls/ca.crt'))

        def request(path, method='GET', value=None, form=False, headers=None):
            if not path.startswith('/') or path.startswith('//'): raise ValueError('Invalid internal identity path')
            connection = http.client.HTTPSConnection('keycloak', 8443, context=tls, timeout=30)
            connection._create_connection = lambda _address, timeout, source_address: socket.create_connection((address, 8443), timeout, source_address)
            values = dict(headers or {}, Host='identity.test.internal', **{'Content-Type': 'application/x-www-form-urlencoded' if form else 'application/json'})
            body = urllib.parse.urlencode(value) if form else json.dumps(value) if value is not None else None
            connection.request(method, path, body, values)
            result = connection.getresponse()
            raw = result.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024: raise ValueError('Identity response bounds exceeded')
            return result.status, result.getheaders(), raw

        stage = 'readiness'
        for _ in range(100):
            if out(['docker', 'inspect', container_id, '--format', '{{.State.Status}}']) != 'running': raise ValueError('Fixture exited before readiness')
            try:
                if request('/realms/platform/.well-known/openid-configuration')[0] == 200: break
            except (OSError, http.client.HTTPException): pass
            time.sleep(2)
        else: raise ValueError('Identity readiness timed out')
        status, _, raw = request('/realms/master/protocol/openid-connect/token', 'POST', dict(grant_type='password', client_id='admin-cli', username='bootstrap-admin', password=admin_secret), form=True)
        if status != 200: raise ValueError('Fixture admin authentication failed')
        admin = json.loads(raw)['access_token']

        def api(path):
            status, _, raw = request('/admin/realms/platform/' + path, headers={'Authorization': 'Bearer ' + admin})
            if status != 200: raise ValueError('Fixture identity metadata read failed')
            return json.loads(raw)

        jwks = json.loads(request('/realms/platform/protocol/openid-connect/certs')[2])
        if set(api('users/' + owner).get('requiredActions', [])) != {'UPDATE_PASSWORD', 'CONFIGURE_TOTP', identity.RECOVERY_ACTION}:
            raise ValueError('Exact owner required enrollment actions were not imported')
        def browser(): return Browser(request, cfg['auth_origin'], client_secret, cfg['admin_origin'] + '/auth/callback', work)
        session = browser()
        stage = 'initial owner enrollment'
        session.start()
        session.post(Forms(session.raw).choose('username'), username='owner', password=temporary)
        otp_secret, recovery_codes = None, None
        for _ in range(8):
            if session.location: break
            forms = Forms(session.raw)
            fields = set().union(*(set(item['fields']) for item in forms.forms))
            enrollment_forms.append(sorted(fields))
            if 'password-new' in fields:
                session.post(forms.choose('password-new'), **{'password-new': password, 'password-confirm': password, 'logout-sessions': 'on'})
            elif 'totpSecret' in fields:
                form = forms.choose('totpSecret')
                otp_secret = form['fields']['totpSecret']
                session.post(form, totp=totp(otp_secret), userLabel='isolated-owner-proof')
            elif 'generatedRecoveryAuthnCodes' in fields:
                form = forms.choose('generatedRecoveryAuthnCodes')
                recovery_codes = form['fields']['generatedRecoveryAuthnCodes'].split(',')
                if len(recovery_codes) != 12 or any(len(code) != 12 for code in recovery_codes): raise ValueError('Generated recovery-code contract differs')
                session.post(form, **{'recovery-codes-confirmation': 'on'})
            elif 'firstName' in fields:
                session.post(forms.choose('firstName'), firstName='Synthetic', lastName='Owner', email='owner@example.invalid')
            else:
                raise ValueError('Unrecognized enrollment form fields: ' + ','.join(sorted(fields)))
        if not session.location or not otp_secret or not recovery_codes: raise ValueError('Owner enrollment did not complete both factors')
        tokens = session.tokens()
        first = session.claims(tokens['access_token'], jwks, owner)
        session.claims(tokens['id_token'], jwks, owner, id_token=True)
        if {'otp', 'totp', 'mfa'} & set(first.get('amr', [])): raise ValueError('Enrollment manufactured a completed MFA claim')
        checks.append('Initial required password/TOTP/recovery enrollment does not manufacture MFA; unchanged control MFA guard rejects its token')

        def password_login():
            value = browser()
            value.start()
            value.post(Forms(value.raw).choose('username'), username='owner', password=password)
            if value.location: raise ValueError('Password alone bypassed the required configured second factor')
            return value

        stage = 'TOTP authenticated PKCE'
        # Enrollment used this TOTP step; Keycloak correctly rejects its replay.
        # Wait for a new step rather than weakening the realm's replay policy.
        time.sleep(31 - time.time() % 30)
        session = password_login()
        session.post(Forms(session.raw).choose('otp'), otp=totp(otp_secret))
        tokens = session.tokens()
        otp_claims = session.claims(tokens['access_token'], jwks, owner)
        session.claims(tokens['id_token'], jwks, owner, id_token=True)
        if 'otp' not in otp_claims.get('amr', []) or 'pwd' not in otp_claims.get('amr', []): raise ValueError('Completed TOTP/password AMR was not proven')
        if 'platform-owner' not in otp_claims.get('realm_access', {}).get('roles', []): raise ValueError('Owner role changed')
        checks.append('Real password plus TOTP PKCE produces signature/issuer/audience/nonce/owner-validated pwd+otp claims')

        def recovery_login():
            value = password_login()
            form = Forms(value.raw).choose('otp')
            value.post(form, tryAnotherWay='on')
            forms = Forms(value.raw)
            selection_forms.append([dict(id=item['id'], fields=sorted(item['fields']), buttons=[dict(name=button['name'], text=' '.join(button['text'].split())[:100]) for button in item['buttons']]) for item in forms.forms])
            choices = [(form, button) for form in forms.forms for button in form['buttons'] if button['name'] == 'authenticationExecution' and 'recovery' in button['text'].lower()]
            if len(choices) == 1:
                form, button = choices[0]
                value.post(form, authenticationExecution=button['value'])
            elif not choices:
                # Keycloak 26.8's default theme presents one form per option
                # with a hidden execution ID instead of named submit buttons.
                options = [form for form in forms.forms if 'authenticationExecution' in form['fields'] and 'recovery' in form['text'].lower()]
                if len(options) != 1: raise ValueError('Exact recovery authenticator selection was unavailable')
                value.post(options[0])
            else: raise ValueError('Ambiguous recovery authenticator selection')
            return value

        stage = 'one-use recovery authenticated PKCE'
        session = recovery_login()
        session.post(Forms(session.raw).choose('recoveryCodeInput'), recoveryCodeInput=recovery_codes[0])
        tokens = session.tokens()
        recovered = session.claims(tokens['access_token'], jwks, owner)
        session.claims(tokens['id_token'], jwks, owner, id_token=True)
        if not {'pwd', 'mfa'} <= set(recovered.get('amr', [])) or 'otp' in recovered.get('amr', []): raise ValueError('Recovery completion did not prove exact password+mfa AMR')
        checks.append('Real password plus recovery PKCE produces validated pwd+mfa claims without falsely claiming OTP or SSO')
        credentials = api('users/' + owner + '/credentials')
        recovery = [item for item in credentials if item['type'] == 'recovery-authn-codes']
        if len(recovery) != 1 or remaining_codes(recovery[0]) != 11: raise ValueError('Recovery credential was not consumed once')
        stage = 'used-code replay rejection'
        replay = recovery_login()
        replay.post(Forms(replay.raw).choose('recoveryCodeInput'), recoveryCodeInput=recovery_codes[0])
        if replay.location or 'recoveryCodeInput' not in set().union(*(set(item['fields']) for item in Forms(replay.raw).forms)): raise ValueError('Used recovery code was not rejected')
        after = [item for item in api('users/' + owner + '/credentials') if item['type'] == 'recovery-authn-codes']
        if len(after) != 1 or remaining_codes(after[0]) != 11: raise ValueError('Replay changed the next usable code')
        checks.append('Used recovery code rejected on a fresh login without token issuance or consuming the next code')
        stage = 'audited owner MFA reset'
        if NODE_IMAGE not in json.loads(out(['docker', 'image', 'inspect', NODE_IMAGE]))[0].get('RepoDigests', []): raise ValueError('Exact verified helper tool image is required')
        helper = Path(__file__).with_name('keycloak-provision.mjs')
        new_temporary = 'Aa1!' + secrets.token_urlsafe(40)
        result = run(['docker', 'run', '--rm', '--pull=never', '--network', network, '--add-host', 'keycloak:' + address, '--read-only', '--user', '10001:10001', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true', '--memory', '256m', '--pids-limit', '64', '--env', 'NODE_EXTRA_CA_CERTS=/etc/autosoft/ca.crt', '--mount', 'type=bind,source=' + str(work / 'tls/ca.crt') + ',target=/etc/autosoft/ca.crt,readonly', '--volume', str(helper) + ':/fixture/keycloak-provision.mjs:ro,z', '-i', NODE_IMAGE, 'node', '/fixture/keycloak-provision.mjs'], input=json.dumps(dict(action='recover-owner', resetTotp=True, bootstrapPassword=admin_secret, ownerSubject=owner, ownerPassword=new_temporary)).encode())
        receipt = json.loads(result.stdout)
        if receipt.get('ownerSubject') != owner or receipt.get('removedTotpCredentials') != 1 or receipt.get('removedRecoveryCredentials') != 1 or receipt.get('recoveryEnrollmentRequired') is not True or receipt.get('sessionsInvalidated') is not True:
            raise ValueError('Exact owner reset receipt differs')
        if any(item['type'] in ('otp', 'recovery-authn-codes') for item in api('users/' + owner + '/credentials')) or not {'UPDATE_PASSWORD', 'CONFIGURE_TOTP', 'CONFIGURE_RECOVERY_AUTHN_CODES'} <= set(api('users/' + owner).get('requiredActions', [])):
            raise ValueError('Owner reset did not revoke both factors and require all enrollment actions')
        status, _, _ = request('/realms/platform/protocol/openid-connect/token', 'POST', dict(grant_type='refresh_token', client_id='autosoft-admin', client_secret=client_secret, refresh_token=tokens['refresh_token']), form=True)
        if status == 200: raise ValueError('Reset failed to revoke the prior authenticated session refresh token')
        checks.append('Actual audited reset helper revokes exact owner OTP and recovery credentials, invalidates refresh session and forces password/TOTP/new-code enrollment')
        report = dict(checkedAt=datetime.now(timezone.utc).isoformat(), status='passed', scope='isolated Keycloak 26.8.0 browser-form/PKCE identity protocol fixture only', keycloakImage=IMAGE, keycloakImageId=inspected['Id'], helperImage=NODE_IMAGE, sourceHashes={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ('identity.py', 'test-identity-login.py', 'bootstrap.py', 'keycloak-provision.mjs')}, checks=checks, modelApiCalls=0, limitations=['Synthetic H2 fixture; production MySQL identity persistence separately tested', 'No visual browser, Microsoft/Google consent or live directory group membership proof', 'Existing signed access tokens may remain valid until their five-minute expiry; Keycloak session/refresh revocation is immediate', 'No full platform acceptance or company security qualification is implied'])
        write(report_path, report)
        print(json.dumps(report, indent=2))
    except Exception as exc:
        # Only our bounded, deliberately non-secret contract errors are emitted.
        diagnostic = str(exc)[:500] if type(exc) is ValueError else type(exc).__name__
        report = dict(checkedAt=datetime.now(timezone.utc).isoformat(), status='failed', scope='isolated Keycloak identity fixture only', keycloakImage=IMAGE, stage=stage, diagnostic=diagnostic, enrollmentFormFields=enrollment_forms, selectionFormMetadata=selection_forms, checks=checks, modelApiCalls=0)
        if stage == 'audited owner MFA reset' and isinstance(exc, subprocess.CalledProcessError):
            # This fixed helper emits only bounded policy/HTTP errors; input
            # credentials travel through stdin and never appear in argv.
            stderr = (exc.stderr or b'').decode(errors='replace')
            report['helperFailure'] = [line[:400] for line in stderr.splitlines() if line.startswith(('Error: ', 'TypeError: '))][:3]
        if container_id:
            failed = json.loads(out(['docker', 'inspect', container_id]))[0]
            report['containerExit'] = {key: failed['State'][key] for key in ('Status', 'ExitCode', 'OOMKilled')}
            logs = out(['docker', 'logs', container_id])
            sensitive = [temporary, password, client_secret, admin_secret, locals().get('otp_secret')]
            sensitive += [item['secret'] for item in realm['clients'] if item.get('secret')]
            sensitive += locals().get('recovery_codes') or []
            for value in sensitive:
                if value: logs = logs.replace(value, '[redacted]')
            write(work / 'redacted-keycloak.log', logs)
            report['serverErrors'] = [line[:400] for line in logs.splitlines() if 'ERROR' in line or 'Caused by' in line][-5:]
        write(report_path, report)
        print(json.dumps(report, indent=2))
        raise SystemExit(1)
    finally:
        if container_id:
            info = json.loads(out(['docker', 'inspect', container_id]))[0]
            if info['Id'] == container_id and info['Name'] == '/' + name and info['Config']['Labels'].get('autosoft.identity.fixture') == test_id:
                run(['docker', 'rm', '-f', container_id])
        networks = json.loads(out(['docker', 'network', 'inspect', network]))
        if len(networks) == 1 and networks[0]['Name'] == network and networks[0]['Labels'].get('autosoft.identity.fixture') == test_id and not networks[0]['Containers']:
            run(['docker', 'network', 'rm', networks[0]['Id']])


if __name__ == '__main__': main()

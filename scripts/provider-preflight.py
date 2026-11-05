#!/usr/bin/env python3
"""Read-only provider authentication checks. Never submits generation requests.

Run on the installation host as root. Credentials stay in host memory and are
sent only to their provider's fixed HTTPS endpoint. No redirects, proxies,
response bodies, credential hashes, or exception messages reach the report.
Google client parsing is a configuration check, not proof of OAuth login.
"""
import argparse
from datetime import datetime, timezone
import http.client
import json
import os
import re
import ssl
import stat

MAX_RESPONSE = 1024 * 1024
ENDPOINTS = {
    'openai': ('api.openai.com', '/v1/models'),
    'anthropic': ('api.anthropic.com', '/v1/models?limit=1000'),
}


def protected_file(path):
    """Reject links, shared files, non-root ownership and broad permissions."""
    if not os.path.isabs(path):
        raise ValueError('An absolute protected file path is required')
    # Opening every parent without following links also rejects a linked parent.
    parts = path.split(os.sep)
    if any(part in ('.', '..') for part in parts):
        raise ValueError('Canonical protected file path required')
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            if not part:
                raise ValueError('Canonical protected file path required')
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or
                    stat.S_IMODE(before.st_mode) not in (0o400, 0o600) or
                    before.st_nlink != 1 or not 0 < before.st_size <= 4096):
                raise ValueError('Root-owned private regular credential file required')
            value = os.read(descriptor, 4097)
            after = os.fstat(descriptor)
            identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid,
                                    row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
            if identity(before) != identity(after) or len(value) != before.st_size:
                raise ValueError('Credential changed while being read')
            return value.decode('utf-8', errors='strict').strip()
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def api_key(text, provider):
    name = provider.upper() + '_API_KEY'
    if text.startswith(name + '='):
        text = unquote(text[len(name) + 1:].strip())
    if not re.fullmatch(r'[A-Za-z0-9_.-]{32,1024}', text):
        raise ValueError('Credential format is not recognized')
    return text


def google_client(text):
    """Accept downloaded web-client JSON, named fields, or ID/secret lines.

    Parsing never evaluates shell syntax. Ambiguous/duplicate entries fail.
    Return secret material only to the host caller, never to report generation.
    """
    fields = {}
    format_name = 'named-fields'
    if text.startswith('{'):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate client field')
                result[key] = value
            return result
        value = json.loads(text, object_pairs_hook=unique)
        if not isinstance(value, dict) or 'installed' in value:
            raise ValueError('A Google web client is required')
        fields = value.get('web', value)
        if not isinstance(fields, dict):
            raise ValueError('Google client object required')
        format_name = 'web-client-json'
    else:
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        aliases = {'clientid': 'client_id', 'googleclientid': 'client_id',
                   'clientsecret': 'client_secret', 'googleclientsecret': 'client_secret'}
        for line in lines:
            match = re.fullmatch(r'([A-Za-z_ ]+)\s*[:=]\s*(.+)', line)
            if match:
                name = aliases.get(re.sub(r'[_ ]', '', match[1]).lower())
                if not name or name in fields:
                    raise ValueError('Unknown or duplicate Google client field')
                fields[name] = unquote(match[2].strip())
            elif len(lines) == 2 and not fields:
                fields = {'client_id': lines[0], 'client_secret': lines[1]}
                format_name = 'id-secret-lines'
                break
            else:
                raise ValueError('Google client format is not recognized')
    client_id, secret = fields.get('client_id'), fields.get('client_secret')
    if (not isinstance(client_id, str) or
            not re.fullmatch(r'[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com', client_id) or
            not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{8,512}', secret)):
        raise ValueError('Google client ID or secret format differs')
    return client_id, secret, format_name


def check_provider(provider, key, connection_factory=http.client.HTTPSConnection):
    host, path = ENDPOINTS[provider]
    headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity'}
    if provider == 'openai':
        headers['Authorization'] = 'Bearer ' + key
    else:
        headers['x-api-key'] = key
        headers['anthropic-version'] = '2023-06-01'
    result = {'authenticationAccepted': False, 'httpStatus': None,
              'modelIds': [], 'catalogComplete': False, 'generationTested': False}
    connection = None
    try:
        # HTTPSConnection ignores proxy environment variables and does not follow
        # Location headers. Certificate and hostname verification remain enabled.
        connection = connection_factory(host, timeout=30, context=ssl.create_default_context())
        connection.request('GET', path, headers=headers)
        response = connection.getresponse()
        result['httpStatus'] = response.status
        if response.status != 200:
            result['status'] = 'authentication-rejected' if response.status in (401, 403) else 'provider-unavailable'
            return result
        if response.getheader('Content-Encoding', 'identity') != 'identity':
            raise ValueError()
        length = response.getheader('Content-Length')
        if length is not None and (not re.fullmatch(r'[0-9]{1,8}', length) or int(length) > MAX_RESPONSE):
            raise ValueError()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE or length is not None and len(body) != int(length):
            raise ValueError()
        value = json.loads(body)
        if not isinstance(value, dict) or not isinstance(value.get('data'), list) or len(value['data']) > 5000:
            raise ValueError()
        ids = []
        for model in value['data']:
            identifier = model.get('id') if isinstance(model, dict) else None
            if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', identifier)
                    or key in identifier):
                raise ValueError()
            ids.append(identifier)
        if len(ids) != len(set(ids)) or provider == 'anthropic' and type(value.get('has_more')) is not bool:
            raise ValueError()
        result.update(authenticationAccepted=True, status='authenticated',
                      modelIds=sorted(ids), catalogComplete=not value.get('has_more', False))
    except Exception:
        result['status'] = 'unconfirmed-response'
    finally:
        if connection is not None:
            connection.close()
    return result


def preflight(paths):
    report = {'schemaVersion': 1, 'checkedAt': datetime.now(timezone.utc).isoformat(),
              'generationRequests': 0, 'modelsQualified': False, 'providers': {}}
    for provider in ENDPOINTS:
        if not paths.get(provider):
            report['providers'][provider] = {'authenticationAccepted': False, 'status': 'not-configured'}
            continue
        try:
            key = api_key(protected_file(paths[provider]), provider)
            report['providers'][provider] = check_provider(provider, key)
        except Exception:
            report['providers'][provider] = {'authenticationAccepted': False, 'status': 'protected-credential-unavailable'}
    if not paths.get('google'):
        report['google'] = {'clientConfigurationRecognized': False, 'status': 'not-configured', 'loginTested': False}
        return report
    try:
        _, _, format_name = google_client(protected_file(paths['google']))
        report['google'] = {'clientConfigurationRecognized': True, 'format': format_name,
                            'loginTested': False, 'requiresBrowserLogin': True}
    except Exception:
        report['google'] = {'clientConfigurationRecognized': False, 'status': 'protected-client-configuration-unavailable', 'loginTested': False}
    return report


def main(args=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openai-key-file')
    parser.add_argument('--anthropic-key-file')
    parser.add_argument('--google-client-file')
    config = parser.parse_args(args)
    paths = {name: value for name, value in {'openai': config.openai_key_file,
             'anthropic': config.anthropic_key_file, 'google': config.google_client_file}.items() if value}
    if not paths:
        parser.error('At least one protected provider/client file is required')
    if os.name != 'posix' or os.geteuid() != 0:
        parser.error('Run as root on the Linux installation host')
    report = preflight(paths)
    print(json.dumps(report, sort_keys=True))
    return 0 if all(report['providers'][name]['authenticationAccepted'] for name in ENDPOINTS if name in paths) and ('google' not in paths or report['google']['clientConfigurationRecognized']) else 1


if __name__ == '__main__':
    raise SystemExit(main())

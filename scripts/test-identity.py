#!/usr/bin/env python3
"""Identity configuration boundary tests; live AMR proof is separate."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('identity', Path(__file__).with_name('identity.py'))
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)
proof_spec = importlib.util.spec_from_file_location('identity_proof', Path(__file__).with_name('test-identity-login.py'))
proof = importlib.util.module_from_spec(proof_spec)
proof_spec.loader.exec_module(proof)
OWNER = '12345678-1234-4234-8234-123456789abc'


def baseline():
    return dict(realm='platform', registrationAllowed=False,
                users=[dict(id=OWNER, username='owner', realmRoles=['platform-owner', 'platform-admin'], requiredActions=['UPDATE_PASSWORD', 'CONFIGURE_TOTP'])],
                clients=[dict(clientId='autosoft-admin', directAccessGrantsEnabled=False, attributes={'pkce.code.challenge.method': 'S256'})],
                identityProviders=[dict(alias='google', postBrokerLoginFlowAlias='platform-sso-otp')],
                authenticatorConfig=[dict(alias='verified-otp', config={'default.reference.value': 'otp'})],
                authenticationFlows=[dict(alias='platform-forms', authenticationExecutions=[
                    dict(authenticator='auth-username-password-form', requirement='REQUIRED', authenticatorConfig='verified-password', priority=10),
                    dict(authenticator='auth-otp-form', requirement='REQUIRED', authenticatorConfig='verified-otp', priority=20)]),
                    dict(alias='platform-sso-otp', authenticationExecutions=[dict(authenticator='auth-otp-form', requirement='REQUIRED')])])


class IdentityTests(unittest.TestCase):
    def test_protocol_fixture_real_otp_vector_and_default_theme_binding(self):
        with patch.object(proof.time, 'time', return_value=59):
            self.assertEqual(proof.totp('12345678901234567890'), '287082')
        forms = proof.Forms('<ul><li><form id="kc-select-credential-form" action="/login"><input type="hidden" name="authenticationExecution" value="otp-id"></form><div role="button">Authenticator application</div></li><li><form id="kc-select-credential-form" action="/login"><input type="hidden" name="authenticationExecution" value="backup-id"></form><div role="button">Recovery authentication code</div></li></ul>')
        choices = [form for form in forms.forms if 'recovery' in form['text'].lower()]
        self.assertEqual(len(choices), 1)
        self.assertEqual(choices[0]['fields']['authenticationExecution'], 'backup-id')

    def test_preserves_owner_roles_sso_clients_and_input(self):
        source = baseline()
        result = identity.owner_recovery_realm(source, OWNER)
        self.assertEqual(source, baseline())
        for key in ('clients', 'identityProviders'):
            self.assertEqual(source[key], result[key])
        self.assertEqual(source['authenticationFlows'][1], result['authenticationFlows'][1])
        self.assertEqual(source['users'][0]['realmRoles'], result['users'][0]['realmRoles'])
        self.assertEqual(result['users'][0]['requiredActions'], ['UPDATE_PASSWORD', 'CONFIGURE_TOTP', identity.RECOVERY_ACTION])

    def test_second_factor_requires_existing_credential_not_role(self):
        result = identity.owner_recovery_realm(baseline(), OWNER)
        forms = result['authenticationFlows'][0]['authenticationExecutions']
        self.assertEqual(forms[0]['authenticator'], 'auth-username-password-form')
        self.assertEqual(forms[0]['requirement'], 'REQUIRED')
        self.assertEqual(forms[1]['requirement'], 'CONDITIONAL')
        branch = result['authenticationFlows'][-1]['authenticationExecutions']
        self.assertEqual([(item['authenticator'], item['requirement']) for item in branch], [('conditional-user-configured', 'REQUIRED'), ('auth-otp-form', 'ALTERNATIVE'), ('auth-recovery-authn-code-form', 'ALTERNATIVE')])
        self.assertEqual(result['authenticatorConfig'][-1]['config']['default.reference.value'], 'mfa')
        self.assertEqual({action['alias'] for action in result['requiredActions'] if action['enabled']}, {'UPDATE_PASSWORD', 'CONFIGURE_TOTP', identity.RECOVERY_ACTION})
        self.assertTrue(all(not action['defaultAction'] for action in result['requiredActions']))

    def test_rejects_authentication_drift_registration_extra_owner_or_federation(self):
        for change in ('registration', 'extra_owner', 'federation', 'owner_subject', 'password_optional', 'password_reference', 'otp_optional', 'no_enrollment', 'duplicate_flow', 'disabled_totp_action'):
            with self.subTest(change=change):
                source = baseline()
                if change == 'registration': source['registrationAllowed'] = True
                elif change == 'extra_owner': source['users'].append(dict(id='another', realmRoles=['platform-owner']))
                elif change == 'federation': source['users'][0]['federatedIdentities'] = [dict(identityProvider='google')]
                elif change == 'owner_subject': source['users'][0]['id'] = 'different'
                elif change == 'password_optional': source['authenticationFlows'][0]['authenticationExecutions'][0]['requirement'] = 'ALTERNATIVE'
                elif change == 'password_reference': source['authenticationFlows'][0]['authenticationExecutions'][0]['authenticatorConfig'] = 'unreviewed'
                elif change == 'otp_optional': source['authenticationFlows'][0]['authenticationExecutions'][1]['requirement'] = 'ALTERNATIVE'
                elif change == 'no_enrollment': source['users'][0]['requiredActions'].remove('CONFIGURE_TOTP')
                elif change == 'duplicate_flow': source['authenticationFlows'].append(dict(alias=identity.RECOVERY_FLOW))
                elif change == 'disabled_totp_action': source['requiredActions'] = [dict(alias='CONFIGURE_TOTP', providerId='CONFIGURE_TOTP', enabled=False)]
                with self.assertRaises(ValueError): identity.owner_recovery_realm(source, OWNER)


if __name__ == '__main__': unittest.main()

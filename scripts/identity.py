#!/usr/bin/env python3
"""Company identity configuration; this module never handles recovery-code values.

The recovery flow must be qualified through real Keycloak browser/PKCE requests
before installation enables it. The platform's token/MFA acceptance is unchanged.
"""
from copy import deepcopy
import re

RECOVERY_ACTION = 'CONFIGURE_RECOVERY_AUTHN_CODES'
RECOVERY_FLOW = 'platform-owner-second-factor'
RECOVERY_REFERENCE = 'verified-owner-recovery'


def owner_recovery_realm(realm, owner_subject):
    """Return a new platform import with password followed by OTP or a backup code.

    A conditional user-configured branch permits initial required enrollment;
    such enrollment does not manufacture a completed MFA execution/AMR claim.
    The control application still refuses any token without verified MFA.
    SSO's separate mandatory OTP flow and all roles/client grants are retained.
    """
    if not isinstance(realm, dict) or realm.get('realm') != 'platform' or realm.get('registrationAllowed') is not False or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', owner_subject):
        raise ValueError('An exact protected platform realm and owner UUID are required')
    result = deepcopy(realm)
    owners = [user for user in result.get('users', []) if 'platform-owner' in user.get('realmRoles', [])]
    if len(owners) != 1 or owners[0].get('id') != owner_subject or owners[0].get('username') != 'owner' or owners[0].get('federationLink') or owners[0].get('federatedIdentities'):
        raise ValueError('Exactly one permanent non-federated platform owner is required')
    flows = result.get('authenticationFlows', [])
    forms = [flow for flow in flows if flow.get('alias') == 'platform-forms']
    if len(forms) != 1 or any(flow.get('alias') == RECOVERY_FLOW for flow in flows):
        raise ValueError('The reviewed platform password/OTP import is required')
    executions = forms[0].get('authenticationExecutions', [])
    if len(executions) != 2 or executions[0].get('authenticator') != 'auth-username-password-form' or executions[0].get('requirement') != 'REQUIRED' or executions[0].get('authenticatorConfig') != 'verified-password' or executions[1].get('authenticator') != 'auth-otp-form' or executions[1].get('requirement') != 'REQUIRED' or executions[1].get('authenticatorConfig') != 'verified-otp':
        raise ValueError('Existing authentication policy differs; do not silently replace it')
    forms[0]['authenticationExecutions'] = [executions[0], dict(flowAlias=RECOVERY_FLOW, authenticatorFlow=True, requirement='CONDITIONAL', priority=20)]
    flows.append(dict(alias=RECOVERY_FLOW, providerId='basic-flow', topLevel=False, builtIn=False, authenticationExecutions=[
        dict(authenticator='conditional-user-configured', authenticatorFlow=False, requirement='REQUIRED', priority=10),
        dict(authenticator='auth-otp-form', authenticatorFlow=False, authenticatorConfig='verified-otp', requirement='ALTERNATIVE', priority=20),
        dict(authenticator='auth-recovery-authn-code-form', authenticatorFlow=False, authenticatorConfig=RECOVERY_REFERENCE, requirement='ALTERNATIVE', priority=30),
    ]))
    configs = result.setdefault('authenticatorConfig', [])
    if any(config.get('alias') == RECOVERY_REFERENCE for config in configs):
        raise ValueError('Recovery authenticator reference already exists')
    # mfa denotes the completed password + second-factor flow. Never label a
    # backup code as OTP, or infer MFA from credential enrollment/account roles.
    configs.append(dict(alias=RECOVERY_REFERENCE, config={'default.reference.value': 'mfa', 'default.reference.maxAge': '1800'}))
    actions = result.setdefault('requiredActions', [])
    if any(action.get('alias') == RECOVERY_ACTION for action in actions):
        raise ValueError('Recovery required action already exists')
    # Providing requiredActions in a realm import replaces Keycloak's default
    # list. User-level action names alone cannot enforce an absent provider.
    for alias, name, priority in [('UPDATE_PASSWORD', 'Update Password', 30), ('CONFIGURE_TOTP', 'Configure OTP', 40)]:
        matching = [action for action in actions if action.get('alias') == alias]
        if matching and (len(matching) != 1 or matching[0].get('providerId') != alias or matching[0].get('enabled') is not True):
            raise ValueError('Password/TOTP required-action providers must remain enabled')
        if not matching:
            actions.append(dict(alias=alias, providerId=alias, name=name, enabled=True, defaultAction=False, priority=priority, config={}))
    actions.append(dict(alias=RECOVERY_ACTION, providerId=RECOVERY_ACTION, name='Recovery Authentication Codes', enabled=True, defaultAction=False, priority=45, config={'warning_threshold': '4'}))
    required = owners[0].setdefault('requiredActions', [])
    if 'CONFIGURE_TOTP' not in required or 'UPDATE_PASSWORD' not in required:
        raise ValueError('Owner password change and TOTP enrollment must remain required')
    required.append(RECOVERY_ACTION)
    return result

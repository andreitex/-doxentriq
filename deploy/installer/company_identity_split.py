"""Separate initial-policy verification using completed, unchanged provision data.

This component has no installer admission or public-start capability. The caller
must bind expected inputs and authority to the genuine same-session HeldParent,
signed source, rendered files and independently confirmed private infrastructure.
Files alone, or a caller-provided Python callback, cannot establish that authority.
"""
from contextlib import ExitStack, nullcontext
import json
import re


def verify_provisioned(data, expected, verification_operation, source, ca, payload, *,
                       check_authority, io_module, evidence_module, commands_class,
                       keycloak_image_id, workspace_context=nullcontext):
    E=evidence_module
    E.require(callable(check_authority) and type(verification_operation) is str
        and re.fullmatch('[a-f0-9]{32}',verification_operation)
        and verification_operation!='0'*32 and verification_operation!=expected['operationId'])
    E.require(type(source) is bytes and E.sha(source)==expected['sourceSha256']
        and type(ca) is bytes and E.sha(ca)==expected['caSha256'])
    E.require(type(payload) is bytes and 0<len(payload)<=65536)
    supplied=json.loads(payload,object_pairs_hook=E.unique_object)
    E.require(type(supplied) is dict and supplied.get('action')=='verify-initial'
        and type(supplied.get('ownerSubject')) is str
        and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',supplied['ownerSubject']))
    # Close this scope before the one declared sibling-directory creation.
    # Directory metadata is never globally refreshed to conceal that mutation.
    with E.ProvisionEvidence(data,expected,check_authority=check_authority) as held:
        before=held.observation()
    check_authority()
    with ExitStack() as stack:
        io=io_module.IdentityIO(data,verification_operation,source,ca,check_authority=check_authority)
        stack.callback(io.close)
        # The caller can hold exact host inputs only after the one declared
        # sibling workspace creation, and must close them before IO cleanup.
        # This callback is a trusted component seam, never installer authority.
        stack.enter_context(workspace_context())
        prior=stack.enter_context(E.ProvisionEvidence(data,expected,check_authority=check_authority))
        E.require(prior.observation()==before)
        commands=commands_class(io,verification_operation,expected['image'],expected['networkId'],
            expected['keycloakId'],keycloak_image_id,provision_evidence=prior)
        stack.callback(commands.close)
        commands.preflight()
        result=commands.run_phase('verify',payload)
        E.require(result['phase']=='verify' and result['configuredPolicyVerified'] is True
            and result['publicStartupAllowed'] is False and commands.container is None)
        E.require(prior.observation()==before)
        io.check();check_authority()
        observation=dict(scope='SEPARATE_INITIAL_IDENTITY_POLICY_READBACK',
            provisionRecordsSha256=E.sha(E.canonical(before)),
            provisionOperationId=expected['operationId'],verificationOperationId=verification_operation,
            verificationContainerId=result['containerId'],ownerSubject=supplied['ownerSubject'],
            configuredPolicyVerified=True,browserMfaQualified=False,
            parentAuthorityEstablished=False,publicStartupAllowed=False)
    # A close/check failure above prevents any successful observation escaping.
    check_authority()
    return observation

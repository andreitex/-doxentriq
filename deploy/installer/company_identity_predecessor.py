"""Reconstruct the confirmed initial identity from both closed helper runs.

The caller already holds genuine parent/source/storage and current private
infrastructure. These records cannot grant authority and do not assert current
live identity policy. Both exact workspaces stay read-only through the caller.
"""
from contextlib import contextmanager, ExitStack


@contextmanager
def confirmed_identity(modules, parent, request, request_raw, worker_sha256,
                       infrastructure_raw, *, data, source, ca, image, component,
                       owner_subject, authority, parent_module):
    Q,S,W,I,RW,E=(modules[n] for n in ('configuration','station','identity_worker',
        'infrastructure_worker','render_worker','identity_evidence'))
    directory='/opt/autosoft-company/evidence/'+request['operationId']+'/'+W.STAGE
    intended=Q.canonical(dict(requestSha256=Q.sha(request_raw),
        actionSha256=W.action(Q,request_raw,worker_sha256),session=parent.arguments.session,
        workerSha256=worker_sha256))
    executed_raw=S.read_protected(directory+'/executed.json',32768)
    executed=I.decode(Q,executed_raw)
    Q.require(executed==W.execution_record(Q,request,request_raw,worker_sha256,
        parent.arguments.session,infrastructure_raw,executed['provision']))
    expected=W.validate_provision(Q,executed['provision'],request=request,source=source,
        ca=ca,image=image,component=component)
    verification_operation=W.operation_ids(Q,request)[1]
    verified_raw=S.read_protected(directory+'/verified.json',32768)
    RW.confirmed(parent_module,parent,W.STAGE,W.action(Q,request_raw,worker_sha256),Q.sha(verified_raw))
    records={directory+'/intent.json':intended,directory+'/executed.json':executed_raw,
             directory+'/verified.json':verified_raw}
    with ExitStack() as stack:
        check_records=stack.enter_context(I.held_records(Q,S,records))
        def check():authority();parent.check();check_records()
        provision=stack.enter_context(E.ProvisionEvidence(data,expected,check_authority=check))
        verify_expected=dict(expected,operationId=verification_operation)
        verification=stack.enter_context(E.VerificationEvidence(data,verify_expected,
            owner_subject=owner_subject,check_authority=check))
        provision_observation=provision.observation()
        Q.require(Q.sha(Q.canonical(provision_observation))==executed['provision']['recordsSha256'])
        verification_observation=verification.observation()
        actual=dict(scope='SEPARATE_INITIAL_IDENTITY_POLICY_READBACK',
            provisionRecordsSha256=Q.sha(Q.canonical(provision_observation)),
            provisionOperationId=expected['operationId'],verificationOperationId=verification_operation,
            verificationContainerId=verification_observation['containerId'],ownerSubject=owner_subject,
            configuredPolicyVerified=True,browserMfaQualified=False,
            parentAuthorityEstablished=False,publicStartupAllowed=False)
        wanted=dict(scope='NATIVE_INITIAL_IDENTITY_POLICY_VERIFIED',executionSha256=Q.sha(executed_raw),
            infrastructureOutcomeSha256=Q.sha(infrastructure_raw),verification=actual,
            configuredPolicyVerified=True,browserMfaQualified=False,publicStartupAllowed=False,backupReady=False)
        Q.require(Q.canonical(wanted)==verified_raw)
        observation=dict(scope='CONFIRMED_INITIAL_IDENTITY_RECORDS_ONLY',
            verifiedOutcomeSha256=Q.sha(verified_raw),
            provisionRecordsSha256=actual['provisionRecordsSha256'],
            verificationRecordsSha256=Q.sha(Q.canonical(verification_observation)),
            ownerSubject=owner_subject,livePolicyVerified=False,publicStartupAllowed=False)
        def recheck():
            check();Q.require(provision.observation()==provision_observation
                and verification.observation()==verification_observation)
        recheck();yield observation,recheck;recheck()

#!/usr/bin/env python3
"""Injected daemon/source controls only; no native process, Docker or scanner."""
import copy
from contextlib import ExitStack
from datetime import datetime, timezone, timedelta
import importlib.util
import io
import itertools
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('isolated_feed_qualification', Path(__file__).with_name('qualify-trivy-feed.py'))
M = importlib.util.module_from_spec(spec); sys.modules[spec.name] = M; spec.loader.exec_module(M)
NOW = datetime(2026, 10, 13, 10, tzinfo=timezone.utc)
IMAGE = 'company.invalid/trivy@sha256:'+'a'*64
ID = 'sha256:'+'b'*64


def scanner_report(case):
    version, release = M.VERSIONS[case].split('-', 1)
    row = dict(Target='/inventory (debian 12.0)', Class='os-pkgs', Type='debian',
               Packages=[dict(Name='libcurl4', Version=version, Release=release, SrcName='curl', SrcVersion=version, SrcRelease=release)])
    if case == 'vulnerable':
        row['Vulnerabilities'] = [dict(VulnerabilityID=M.CVE, PkgName='libcurl4', InstalledVersion=M.VERSIONS[case],
            FixedVersion=M.VERSIONS['fixed'], Severity='HIGH', DataSource=dict(ID='debian'))]
    return dict(SchemaVersion=2, Trivy=dict(Version=M.VERSION), ArtifactName='/inventory', ArtifactType='filesystem',
                Metadata=dict(OS=dict(Family='debian', Name='12.0')), Results=[row])


def inputs():
    image = [dict(Id=ID, Os='linux', Architecture='amd64', RepoDigests=[IMAGE],
                  Descriptor=dict(digest=ID, mediaType='application/vnd.oci.image.manifest.v1+json', size=1055),
                  Config=dict(Env=['PATH=/usr/local/bin:/usr/bin'], Volumes=None))]
    company = dict(schemaVersion=1, status='company_approved_scanner', image=IMAGE, version=M.VERSION,
                   entrypoint='/usr/local/bin/trivy', imageInspectSHA256=M.digest(M.canonical(image)))
    feed = dict(directory='/srv/autosoft/validation/trivy-feed-stream-v1-'+'f'*32+'/data/security-cache/trivy/db',
                db=dict(bytes=1607704576, sha256='d'*64), metadata=dict(bytes=148, sha256='e'*64),
                timestamps=dict(Version=2, UpdatedAt='2026-10-13T01:00:00Z', DownloadedAt='2026-10-13T02:00:00Z', NextUpdate='2026-10-14T01:00:00Z'))
    op = '1'*32
    scope = dict(schemaVersion=1, status='root_authorized_isolated_probe_once', operationId=op,
                 notBefore=(NOW-timedelta(minutes=1)).isoformat().replace('+00:00','Z'),
                 expiresAt=(NOW+timedelta(minutes=20)).isoformat().replace('+00:00','Z'), maximumInvocations=1,
                 nativeDispatch=False, root='/srv/autosoft/validation/trivy-isolated-scanner-v1-'+op,
                 companyEvidence=dict(sha256=M.digest(M.canonical(company)), bytes=len(M.canonical(company))),
                 feedEvidence=dict(sha256=M.digest(M.canonical(feed)), bytes=len(M.canonical(feed))), limits=copy.deepcopy(M.LIMITS))
    return scope, company, feed, image


class Journal:
    def __init__(self, fail=None): self.records = {}; self.commands = []; self.fail = fail; self.closed = 0; self.bytes = 0
    def begin(self, scope, fixtures):
        if self.fail == 'begin': raise OSError('injected')
        self.put('intent.json', M.canonical(scope))
        self.fixtures = fixtures
    def put(self, name, raw):
        if self.fail == name or self.fail == 'capacity': raise M.Unavailable('journal_capacity')
        M.require(name not in self.records and len(self.records) < M.LIMITS['evidenceFiles']
                  and self.bytes+len(raw) <= M.LIMITS['evidenceBytes'], 'journal_capacity')
        self.records[name] = raw; self.bytes += len(raw)
        if name == 'result.json' and self.fail == 'terminal-close':
            self.terminal_unknown_refs = (70, 71)
            raise OSError('injected final reopened descriptor close failure')
    def command(self, raw):
        if self.fail == 'command': raise OSError('injected')
        M.require(self.bytes+len(raw)+1 <= M.LIMITS['evidenceBytes'], 'journal_capacity')
        self.commands.append(M.parse(raw)); self.bytes += len(raw)+1
    def close(self):
        self.closed += 1
        if self.fail == 'close': raise OSError('injected')


class Guard:
    def __init__(self, fail=None): self.fail = fail; self.calls = []; self.closed = 0
    def verify(self, feed, deadline, hash_content=True):
        self.calls.append(hash_content)
        if self.fail == 'before' or self.fail == 'after' and len(self.calls) == 5: raise M.Unavailable('feed_content_pin')
    def close(self):
        self.closed += 1
        if self.fail == 'close': raise OSError('injected')


def inspection(identifier, request):
    h = dict(Runtime='runsc', NetworkMode='none', IpcMode='private', PidMode='', UTSMode='', UsernsMode='',
             ReadonlyRootfs=True, Privileged=False, AutoRemove=False, Memory=M.LIMITS['memoryBytes'],
             MemorySwap=M.LIMITS['memoryBytes'], NanoCpus=M.LIMITS['nanoCpus'], PidsLimit=64,
             CapDrop=['ALL'], Tmpfs=M.TMPFS, RestartPolicy=dict(Name='no', MaximumRetryCount=0),
             SecurityOpt=['no-new-privileges'], LogConfig=dict(Type='none'), OomKillDisable=False)
    mounts = [dict(Type='bind', Source=v['source'], Destination=v['target'], RW=False, Propagation='rprivate') for v in request['mounts']]
    mounts += [dict(Type='tmpfs', Destination=key) for key in M.TMPFS]
    return dict(Id=identifier, Name='/'+request['name'], Image=IMAGE.split('@')[1],
        ImageManifestDescriptor=copy.deepcopy(request['imageDescriptor']), Platform='linux', Config=dict(Image=IMAGE,
        Cmd=request['arguments'], Entrypoint=[request['entrypoint']], User='10001:10001', WorkingDir='/',
        Env=[request['environment'][-1], *request['environment'][:-1]], Labels={'io.autosoft.feed-qualification':request['operationId']}, Healthcheck=dict(Test=['NONE'])),
        HostConfig=h, Mounts=mounts, State=dict(Status='created', Running=False, Pid=0, ExitCode=0,
            StartedAt='0001-01-01T00:00:00Z', FinishedAt='0001-01-01T00:00:00Z', OOMKilled=False, Dead=False, Paused=False, Restarting=False))


class Daemon:
    native = False
    def __init__(self, journal, scope, company, feed, image, fail=None):
        self.journal, self.scope, self.company, self.feed, self.image = journal, scope, company, feed, image
        self.fail = fail; self.calls = []; self.containers = {}; self.created = 0; self.closed = 0
    def call(self, args, seconds, out_cap, err_cap):
        self.calls.append(args); verb = args[0]
        if verb == 'image':
            raw = M.canonical(self.image)
            if self.fail == 'image': raw += b' '
            return M.CommandResult(raw)
        if verb == 'create':
            self.created += 1; identifier = f'{self.created:064x}'
            case = next(v for v in args if v.startswith('--name=')).rsplit('-', 1)[1]
            request = M.request(self.scope, self.company, self.feed, case, self.image[0]['Config']['Env'], ID,
                                M.selected_manifest(self.image[0]))
            self.containers[identifier] = (case, inspection(identifier, request))
            if self.fail == 'create_unknown': return M.CommandResult(b'', exit_code=None)
            return M.CommandResult((identifier+'\n').encode(), exit_code=None if self.fail == 'create_ack' else 0)
        identifier = args[-1] if verb in ('inspect','start','stop','rm') else None
        if verb == 'inspect':
            if identifier not in self.containers: return M.CommandResult(b'[]')
            case, value = self.containers[identifier]; value = copy.deepcopy(value)
            if self.fail == 'foreign': value['Name'] = '/other'
            if self.fail == 'drift' and value['State']['Status'] == 'exited': value['HostConfig']['NetworkMode'] = 'host'
            return M.CommandResult(M.canonical([value]))
        if verb == 'start':
            case, value = self.containers[identifier]; value['State'].update(Status='exited', Running=False, StartedAt='2026-10-13T10:00:00Z', FinishedAt='2026-10-13T10:00:01Z')
            raw = b'Version: 0.75.0\n' if case == 'version' else M.canonical(scanner_report(case))
            if self.fail == 'version' and case == 'version': raw = b'Version: 0.74.0\n'
            if self.fail == 'overflow': raw = b'x'*(out_cap+1)
            if self.fail == 'bad_report' and case == 'vulnerable': raw = b'{}'
            if self.fail == 'nonzero': value['State']['ExitCode'] = 1
            return M.CommandResult(raw, exit_code=None if self.fail == 'start_ack' else (1 if self.fail == 'nonzero' else 0))
        if verb == 'stop':
            self.containers[identifier][1]['State'].update(Status='exited', Running=False); return M.CommandResult()
        if verb == 'rm':
            del self.containers[identifier]; return M.CommandResult(exit_code=None if self.fail == 'cleanup_ack' else 0)
        if verb == 'ps': return M.CommandResult()
        raise AssertionError('unexpected adapter verb')
    def close(self):
        self.closed += 1
        if self.fail == 'close': raise OSError('injected')


class Controls(unittest.TestCase):
    def make(self, fail=None, journal_fail=None, guard_fail=None):
        s,c,f,i = inputs(); j = Journal(journal_fail); g = Guard(guard_fail); d = Daemon(j,s,c,f,i,fail)
        q = M.Qualification(d,j,g,clock=lambda:100.,utc=lambda:NOW)
        return q,s,c,f,d,j,g
    def run_case(self, **options):
        q,s,c,f,d,j,g = self.make(**options); return q.run(s,c,f),q,d,j,g
    def test_valid_two_actual_format_reports_and_cleanup(self):
        r,q,d,j,g = self.run_case()
        self.assertEqual(r['status'],'isolated_os_probe_verified'); self.assertEqual(len(r['cases']),2)
        self.assertEqual(d.created,3); self.assertFalse(d.containers); self.assertFalse(q.pending)
        self.assertTrue(r['cleanupConfirmed']); self.assertTrue(r['originalFeedPreserved']); self.assertFalse(r['nativeObserved'])
        self.assertLessEqual(len(j.records)+1,40); self.assertEqual(g.calls,[True,False,False,False,True])
    def test_default_cli_does_not_construct_native_adapter(self):
        with patch.object(M,'NativeDaemon',side_effect=AssertionError('native called')),patch('sys.stdout',new_callable=io.StringIO) as out:
            self.assertEqual(M.main([]),2); self.assertIn('native_dispatch_disabled',out.getvalue())
    def test_native_adapter_rejected_without_explicit_dispatch(self):
        q,s,c,f,d,j,g=self.make(); d.native=True
        with self.assertRaisesRegex(M.Unavailable,'native_dispatch_disabled'): q.run(s,c,f)
        self.assertEqual(d.calls,[]); self.assertEqual(j.records,{})
    def test_scope_boolean_numeric_aliases_rejected(self):
        for key in ('schemaVersion','maximumInvocations'):
            q,s,c,f,d,j,g=self.make();s[key]=True
            with self.assertRaises(M.Unavailable):q.run(s,c,f)
            self.assertFalse(d.calls)
    def test_expired_scope_rejected_before_admission(self):
        q,s,c,f,d,j,g=self.make();s['expiresAt']='2026-10-13T09:00:00Z'
        with self.assertRaises(M.Unavailable):q.run(s,c,f)
        self.assertFalse(j.records)
    def test_changed_independent_feed_pin_refused(self):
        q,s,c,f,d,j,g=self.make();f['db']['sha256']='a'*64
        with self.assertRaisesRegex(M.Unavailable,'independent_evidence_binding'):q.run(s,c,f)
        self.assertFalse(d.calls)
    def test_latest_or_unapproved_image_and_version_denied(self):
        for key,value in (('image','company.invalid/trivy:latest'),('status','installed'),('version','0.74.0')):
            q,s,c,f,d,j,g=self.make();c[key]=value;s['companyEvidence']=dict(sha256=M.digest(M.canonical(c)),bytes=len(M.canonical(c)))
            with self.assertRaisesRegex(M.Unavailable,'unsupported_or_unapproved_scanner'):q.run(s,c,f)
    def test_mutated_limits_and_unsafe_paths_refused(self):
        for key,value in (('root','/srv/autosoft'),('limits',dict(M.LIMITS,memoryBytes=2**50))):
            q,s,c,f,d,j,g=self.make();s[key]=value
            with self.assertRaises(M.Unavailable):q.run(s,c,f)
    def test_guard_failure_after_durable_intent_before_daemon(self):
        r,q,d,j,g=self.run_case(guard_fail='before');self.assertEqual(r['status'],'unavailable')
        self.assertFalse(d.calls);self.assertTrue(q.pending);self.assertEqual(g.closed,1)
        self.assertIn('intent.json',j.records)
    def test_image_measured_identity_drift_refuses_create(self):
        r,q,d,j,g=self.run_case(fail='image');self.assertEqual(r['failureCode'],'company_image_measurement');self.assertEqual(d.created,0)
    def test_readonly_request_no_network_secret_socket_or_relabel(self):
        q,s,c,f,d,j,g=self.make();v=M.request(s,c,f,'vulnerable',['PATH=/usr/bin'],ID,M.selected_manifest(d.image[0]));args=M.create_argv(v);text=' '.join(args)
        for required in ('--runtime=runsc','--network=none','--read-only','--user=10001:10001','--cap-drop=ALL','--pull=never','readonly,bind-propagation=rprivate','--cache-backend=memory'):
            self.assertIn(required,text)
        for forbidden in ('docker.sock',':ro,z',':Z','--privileged','--rm','--network=host','TRIVY_PASSWORD','--device'):
            self.assertNotIn(forbidden,text)
    def test_unknown_create_never_cleans_by_name_or_runs_second(self):
        r,q,d,j,g=self.run_case(fail='create_unknown');self.assertTrue(q.pending);self.assertEqual(d.created,1)
        self.assertFalse(r['cleanupConfirmed']);self.assertFalse(any(v[0] in ('start','stop','rm') for v in d.calls))
    def test_lost_create_ack_only_cleans_independently_owned_id(self):
        r,q,d,j,g=self.run_case(fail='create_ack');self.assertEqual(r['status'],'unavailable');self.assertTrue(q.pending)
        self.assertFalse(any(v[0]=='start' for v in d.calls));self.assertFalse(d.containers)
    def test_unknown_start_retained_and_no_second_case(self):
        r,q,d,j,g=self.run_case(fail='start_ack');self.assertEqual(r['status'],'unavailable');self.assertTrue(q.pending)
        self.assertEqual(d.created,1);self.assertFalse(d.containers)
    def test_ambiguous_cleanup_never_counts_success(self):
        r,q,d,j,g=self.run_case(fail='cleanup_ack');self.assertEqual(r['status'],'unavailable');self.assertTrue(q.pending)
        self.assertEqual(d.created,1);self.assertFalse(r['cleanupConfirmed'])
    def test_foreign_profile_has_no_cleanup_authority(self):
        r,q,d,j,g=self.run_case(fail='foreign');self.assertFalse(r['cleanupConfirmed']);self.assertTrue(q.pending)
        self.assertFalse(any(v[0] in ('start','stop','rm') for v in d.calls))
    def test_after_start_profile_drift_retains_unknown_owned_id(self):
        r,q,d,j,g=self.run_case(fail='drift');self.assertFalse(r['cleanupConfirmed']);self.assertTrue(d.containers)
        self.assertFalse(any(v[0]=='rm' for v in d.calls))
    def test_output_overflow_denies_second_case(self):
        r,q,d,j,g=self.run_case(fail='overflow');self.assertEqual(r['status'],'unavailable');self.assertEqual(d.created,1)
    def test_nonzero_container_or_cli_result_denied(self):
        r,q,d,j,g=self.run_case(fail='nonzero');self.assertEqual(r['status'],'unavailable');self.assertFalse(d.containers)
    def test_version_observation_must_match_approved_version(self):
        r,q,d,j,g=self.run_case(fail='version');self.assertEqual(r['failureCode'],'scanner_version');self.assertEqual(d.created,1)
    def test_invalid_positive_report_blocks_fixed_probe(self):
        r,q,d,j,g=self.run_case(fail='bad_report');self.assertEqual(r['status'],'unavailable');self.assertEqual(d.created,2)
    def test_stale_or_partial_feed_refused(self):
        q,s,c,f,d,j,g=self.make();f['timestamps']['NextUpdate']='2026-10-13T05:00:00Z';s['feedEvidence']=dict(sha256=M.digest(M.canonical(f)),bytes=len(M.canonical(f)))
        with self.assertRaisesRegex(M.Unavailable,'feed_freshness'):q.run(s,c,f)
    def test_advisory_positive_and_fixed_negative(self):
        self.assertTrue(M.report(M.canonical(scanner_report('vulnerable')),'vulnerable')['expectedAdvisoryPresent'])
        self.assertFalse(M.report(M.canonical(scanner_report('fixed')),'fixed')['expectedAdvisoryPresent'])
    def test_positive_missing_advisory_and_negative_present_advisory_refused(self):
        value=scanner_report('vulnerable');del value['Results'][0]['Vulnerabilities']
        with self.assertRaisesRegex(M.Unavailable,'advisory_boundary'):M.report(M.canonical(value),'vulnerable')
        value=scanner_report('fixed');v=scanner_report('vulnerable')['Results'][0]['Vulnerabilities'][0];v['InstalledVersion']=M.VERSIONS['fixed'];value['Results'][0]['Vulnerabilities']=[v]
        with self.assertRaisesRegex(M.Unavailable,'advisory_boundary'):M.report(M.canonical(value),'fixed')
    def test_wrong_artifact_empty_inventory_version_alias_and_severity_denied(self):
        for variant in ('artifact','empty','bool','severity','source'):
            value=scanner_report('vulnerable');row=value['Results'][0]
            if variant=='artifact':value['ArtifactType']='container_image'
            if variant=='empty':row['Packages']=[]
            if variant=='bool':row['Packages'][0]['Epoch']=False
            if variant=='severity':row['Vulnerabilities'][0]['Severity']='LOW'
            if variant=='source':row['Packages'][0]['SrcName']='foreign'
            with self.assertRaises(M.Unavailable):M.report(M.canonical(value),'vulnerable')
    def test_duplicate_case_alias_nonfinite_truncated_and_oversized_json(self):
        for raw in (b'{"SchemaVersion":2,"schemaversion":2}',b'{"a":NaN}',b'{',b'x'*(2*1024**2+1)):
            with self.assertRaises(M.Unavailable):M.parse(raw)
    def test_journal_failure_before_create_and_failed_final_result(self):
        r,q,d,j,g=self.run_case(journal_fail='create-intent-version.json');self.assertEqual(d.created,0);self.assertTrue(q.pending)
        r,q,d,j,g=self.run_case(journal_fail='result.json');self.assertEqual(r['failureCode'],'result_retention_failed');self.assertFalse(r['scopedReadOnlyLookupVerified']);self.assertTrue(q.pending)
    def test_all_release_failures_deny_success(self):
        for options in (dict(fail='close'),dict(journal_fail='close'),dict(guard_fail='close'),dict(guard_fail='after')):
            r,q,d,j,g=self.run_case(**options);self.assertEqual(r['status'],'unavailable');self.assertTrue(q.pending)
            self.assertGreaterEqual(g.closed,1);self.assertGreaterEqual(d.closed,1);self.assertGreaterEqual(j.closed,1)
    def test_one_shot_and_call_limit(self):
        q,s,c,f,d,j,g=self.make();q.run(s,c,f)
        with self.assertRaisesRegex(M.Unavailable,'one_shot_consumed'):q.run(s,c,f)
        q.calls=M.LIMITS['daemonCalls']
        with self.assertRaisesRegex(M.Unavailable,'daemon_call_cap'):q.call(['image','inspect',IMAGE])
    def test_elapsed_deadline_prevents_admitted_daemon_call(self):
        q,s,c,f,d,j,g=self.make();q.start=100.;q.clock=lambda:581.
        with self.assertRaisesRegex(M.Unavailable,'operation_deadline'):q.call(['inspect','a'*64])
        self.assertFalse(d.calls)
    def test_fixture_is_finite_dpkg_text_without_executable_payload(self):
        for case in M.VERSIONS:
            values=M.fixture(case);self.assertEqual(set(values),{'etc/os-release','etc/debian_version','var/lib/dpkg/status'})
            self.assertLess(sum(map(len,values.values())),4096);self.assertIn(('Version: '+M.VERSIONS[case]).encode(),values['var/lib/dpkg/status'])
    def test_narrow_success_preserves_all_unqualified_claims(self):
        r,q,d,j,g=self.run_case()
        for key in ('companySecurityEligible','publisherSignatureVerified','fullDbIntegrityVerified','nativeImageScannerQualified','javaCoverageQualified','globalDailyFeedQualified','backupReady','controllerMemoryLimitEnforced','hostQuotaEnforced','productionQualified','remoteCancellationProven','automaticRetry'):
            self.assertIs(r[key],False)


class ImageAndEnvironmentBindings(unittest.TestCase):
    def profile(self):
        s,c,f,image=inputs(); spec=M.request(s,c,f,'version',image[0]['Config']['Env'],ID,M.selected_manifest(image[0]))
        identifier='c'*64
        return identifier,spec,inspection(identifier,spec)
    def denied(self,mutate,reason='container_identity'):
        identifier,spec,value=self.profile();mutate(value)
        with self.assertRaisesRegex(M.Unavailable,reason):M.inspect_owned(M.canonical([value]),identifier,spec)
    def test_distinct_index_and_selected_manifest_with_reordered_environment(self):
        identifier,spec,value=self.profile();self.assertNotEqual(value['Image'],spec['imageId'])
        state,baseline=M.inspect_owned(M.canonical([value]),identifier,spec)
        self.assertEqual(state['Status'],'created');self.assertEqual(value['ImageManifestDescriptor']['digest'],ID)
        for order in itertools.permutations(spec['environment']):
            value['Config']['Env']=list(order)
            self.assertEqual(M.inspect_owned(M.canonical([value]),identifier,spec,baseline)[1],baseline)
    def test_wrong_container_index_cannot_substitute_selected_manifest(self):
        for image in (ID,'sha256:'+'f'*64):
            self.denied(lambda value:image_change(value,image))
    def test_descriptor_digest_must_be_exact_selected_manifest(self):
        self.denied(lambda value:value['ImageManifestDescriptor'].update(digest=IMAGE.split('@')[1]))
    def test_descriptor_size_is_exact_and_strictly_typed(self):
        for size in (True,False,1055.0,1056,'1055',0,4*1024**2+1):
            self.denied(lambda value,size=size:value['ImageManifestDescriptor'].update(size=size))
    def test_descriptor_media_type_is_exact(self):
        for media in ('application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.v2+json',None):
            self.denied(lambda value,media=media:value['ImageManifestDescriptor'].update(mediaType=media))
    def test_descriptor_platform_variant_and_extra_fields_denied(self):
        for platform in ({'architecture':'arm64','os':'linux'},{'architecture':'amd64','os':'windows'},
                         {'architecture':'amd64','os':'linux','variant':'v1'},None):
            self.denied(lambda value,platform=platform:value['ImageManifestDescriptor'].update(platform=platform))
        self.denied(lambda value:value['ImageManifestDescriptor'].update(annotations={}))
    def test_missing_selected_descriptor_denied(self):
        self.denied(lambda value:value.pop('ImageManifestDescriptor'))
    def test_wrong_config_reference_and_environment_values_denied(self):
        self.denied(lambda value:value['Config'].update(Image='foreign.invalid/image@'+ID))
        self.denied(lambda value:value['Config'].update(Env=['PATH=/foreign','HOME=/tmp','TMPDIR=/tmp']))
    def test_environment_duplicate_names_even_equal_values_denied(self):
        for env in (['HOME=/tmp','HOME=/tmp','TMPDIR=/tmp'],['HOME=/tmp','HOME=/foreign','TMPDIR=/tmp']):
            self.denied(lambda value,env=env:value['Config'].update(Env=env),'container_environment')
    def test_environment_missing_extra_or_changed_names_denied(self):
        for env in (['HOME=/tmp','TMPDIR=/tmp'],['path=/usr/local/bin:/usr/bin','HOME=/tmp','TMPDIR=/tmp']):
            self.denied(lambda value,env=env:value['Config'].update(Env=env))
        self.denied(lambda value:value['Config'].update(Env=['PATH=/usr/local/bin:/usr/bin','HOME=/tmp','TMPDIR=/tmp','EXTRA=x']),'container_environment')
    def test_environment_invalid_types_names_and_controls_denied(self):
        for env in (None,{},[True],['HOME'],['1HOME=/tmp'],['HOME=/tmp\n'],['HOME=/tmp\r'],['HOME=/tmp\x00']):
            self.denied(lambda value,env=env:value['Config'].update(Env=env),'container_environment')
    def test_authenticated_bad_selected_descriptor_stops_before_create(self):
        for variant in ('digest','size_bool','size_zero','size_large','media','platform','variant','extra','missing'):
            q,s,c,f,d,j,g=Controls().make();descriptor=d.image[0]['Descriptor']
            if variant=='digest':descriptor['digest']=IMAGE.split('@')[1]
            elif variant=='size_bool':descriptor['size']=True
            elif variant=='size_zero':descriptor['size']=0
            elif variant=='size_large':descriptor['size']=4*1024**2+1
            elif variant=='media':descriptor['mediaType']='application/vnd.oci.image.index.v1+json'
            elif variant=='platform':descriptor['platform']={'architecture':'arm64','os':'linux'}
            elif variant=='variant':descriptor['platform']={'architecture':'amd64','os':'linux','variant':'v1'}
            elif variant=='extra':descriptor['annotations']={}
            else:del d.image[0]['Descriptor']
            c['imageInspectSHA256']=M.digest(M.canonical(d.image));s['companyEvidence']=dict(sha256=M.digest(M.canonical(c)),bytes=len(M.canonical(c)))
            result=q.run(s,c,f);self.assertEqual(result['status'],'unavailable');self.assertEqual(d.created,0)
            self.assertFalse(any(v[0] in ('start','stop','rm') for v in d.calls))
    def test_exact_present_platform_and_supported_media_require_authenticated_bytes(self):
        for media in ('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'):
            image=inputs()[3][0];image['Descriptor'].update(mediaType=media,platform={'architecture':'amd64','os':'linux'})
            self.assertEqual(M.selected_manifest(image),image['Descriptor'])
    def test_descriptor_change_cannot_rebase_existing_cleanup_profile(self):
        identifier,spec,value=self.profile();_,baseline=M.inspect_owned(M.canonical([value]),identifier,spec)
        changed=copy.deepcopy(spec);changed['imageDescriptor']['size']+=1
        value['ImageManifestDescriptor']=changed['imageDescriptor']
        with self.assertRaisesRegex(M.Unavailable,'container_profile_drift'):
            M.inspect_owned(M.canonical([value]),identifier,changed,baseline)
    def test_first_container_descriptor_mismatch_has_no_start_or_cleanup_authority(self):
        q,s,c,f,d,j,g=Controls().make(); original=d.call
        def altered(args,*rest):
            result=original(args,*rest)
            if args[0]=='inspect':
                rows=M.parse(result.stdout);rows[0]['ImageManifestDescriptor']['digest']=IMAGE.split('@')[1]
                return M.CommandResult(M.canonical(rows))
            return result
        with patch.object(d,'call',side_effect=altered):result=q.run(s,c,f)
        self.assertEqual(result['failureCode'],'container_identity');self.assertFalse(result['cleanupConfirmed'])
        self.assertTrue(q.pending);self.assertEqual(d.created,1)
        self.assertFalse(any(v[0] in ('start','stop','rm') for v in d.calls))
    def test_first_container_duplicate_environment_has_no_start_or_cleanup_authority(self):
        q,s,c,f,d,j,g=Controls().make();original=d.call
        def altered(args,*rest):
            result=original(args,*rest)
            if args[0]=='inspect':
                rows=M.parse(result.stdout);rows[0]['Config']['Env']=['HOME=/tmp','HOME=/tmp','TMPDIR=/tmp']
                return M.CommandResult(M.canonical(rows))
            return result
        with patch.object(d,'call',side_effect=altered):result=q.run(s,c,f)
        self.assertEqual(result['failureCode'],'container_environment');self.assertFalse(result['cleanupConfirmed'])
        self.assertTrue(q.pending);self.assertEqual(d.created,1)
        self.assertFalse(any(v[0] in ('start','stop','rm') for v in d.calls))


def image_change(value,image):
    value['Image']=image


def fake_stat(**changes):
    values=dict(st_dev=44,st_ino=55,st_mode=M.stat.S_IFDIR|0o700,st_uid=0,st_gid=0,
                st_nlink=1,st_size=0,st_mtime_ns=100,st_ctime_ns=100)
    values.update(changes); return SimpleNamespace(**values)


class FakePipe:
    def __init__(self,number,fail=False):self.number=number;self.closed=0;self.fail=fail
    def fileno(self):return self.number
    def close(self):
        self.closed+=1
        if self.fail:raise OSError('injected')


class FakeSelector:
    def __init__(self,fail=False):self.rows={};self.closed=0;self.fail=fail
    def register(self,pipe,event,cap):self.rows[pipe]=SimpleNamespace(fileobj=pipe,data=cap)
    def unregister(self,pipe):del self.rows[pipe]
    def get_map(self):return self.rows
    def select(self,_):return [(value,1) for value in list(self.rows.values())]
    def close(self):
        self.closed+=1
        if self.fail:raise OSError('injected')


class NativeSeams(unittest.TestCase):
    """Every OS/process seam is injected: no POSIX child or Docker operation."""
    def daemon_call(self,variant=None):
        trace=[];state=fake_stat();selector=FakeSelector(variant=='selector_close')
        out=FakePipe(10,variant=='stdout_close');err=FakePipe(11,variant=='stderr_close')
        def wait(timeout):
            trace.append(('wait',timeout))
            if variant=='wait':raise TimeoutError('injected')
            return 0
        process=SimpleNamespace(pid=1234,stdout=out,stderr=err,wait=wait)
        daemon=M.NativeDaemon.__new__(M.NativeDaemon)
        daemon.config='/fixed/config';daemon.socket_fd=8;daemon.socket=M.metadata(state)
        daemon.processes=[];daemon.uncertain=False
        def waitid(*args):
            trace.append(('waitid',))
            if variant=='ownership':raise ChildProcessError('injected')
            return object()
        def killpg(pid,sig):
            trace.append(('kill',pid,sig))
            if sig==0:
                if variant!='group_alive':raise ProcessLookupError()
            elif variant=='kill':raise PermissionError('injected')
        def close(fd):
            trace.append(('close',fd))
            if variant=='pidfd_close' and fd==42:raise OSError('injected')
        def read(fd,size):
            if variant=='pipe':raise OSError('injected')
            return b'x'*3 if variant=='overflow' else b''
        def pidfd(*args):
            if variant=='pidfd':raise OSError('injected')
            return 42
        with ExitStack() as stack:
            for name,value in (('P_PID',1),('WEXITED',4),('WNOHANG',1),('WNOWAIT',16),
                               ('waitid',waitid),('killpg',killpg),('pidfd_open',pidfd),('set_blocking',lambda *_:None),
                               ('fstat',lambda _:state),('read',read),('close',close)):
                stack.enter_context(patch.object(M.os,name,value,create=True))
            stack.enter_context(patch.object(M.signal,'SIGCHLD',17,create=True))
            stack.enter_context(patch.object(M.signal,'SIGKILL',9,create=True))
            stack.enter_context(patch.object(M.signal,'getsignal',return_value=M.signal.SIG_DFL))
            stack.enter_context(patch.object(M.threading,'active_count',return_value=1))
            stack.enter_context(patch.object(M.Path,'lstat',return_value=state))
            stack.enter_context(patch.object(M.selectors,'DefaultSelector',return_value=selector))
            stack.enter_context(patch.object(M.time,'monotonic',return_value=100.))
            constructor=stack.enter_context(patch.object(M.subprocess,'Popen',return_value=process))
            result=daemon.call(['inspect','a'*64],10,2 if variant=='overflow' else 200,100)
            if daemon.uncertain:
                with self.assertRaisesRegex(M.Unavailable,'daemon_cleanup_unknown'):
                    daemon.call(['inspect','a'*64],10,200,100)
                self.assertEqual(constructor.call_count,1)
        return result,daemon,trace,selector,out,err

    def test_owned_leader_terminated_before_reap_even_after_success(self):
        result,d,trace,s,out,err=self.daemon_call();M.known(result)
        kill=trace.index(('kill',1234,9));reap=trace.index(('wait',5));observe=trace.index(('kill',1234,0))
        self.assertLess(kill,reap);self.assertLess(reap,observe);self.assertEqual(d.processes,[])
        self.assertEqual((s.closed,out.closed,err.closed),(1,1,1))

    def test_lost_reaper_authority_never_signals_or_waits(self):
        result,d,trace,*_=self.daemon_call('ownership')
        self.assertFalse(result.reaped);self.assertTrue(d.uncertain);self.assertTrue(d.processes)
        self.assertFalse(any(v[0] in ('kill','wait') for v in trace))

    def test_pidfd_pipe_overflow_and_all_release_failures_deny(self):
        for variant in ('pidfd','pipe','overflow','kill','wait','group_alive','pidfd_close','selector_close','stdout_close','stderr_close'):
            with self.subTest(variant=variant):
                result,d,trace,s,out,err=self.daemon_call(variant)
                with self.assertRaises(M.Unavailable):M.known(result)
                self.assertEqual((s.closed,out.closed,err.closed),(0 if variant=='pidfd' else 1,1,1))
                if variant in ('kill','wait','group_alive','pidfd_close','selector_close','stdout_close','stderr_close'):
                    self.assertTrue(d.uncertain);self.assertTrue(d.processes)

    def test_insufficient_cleanup_reserve_refuses_before_process_creation(self):
        d=M.NativeDaemon.__new__(M.NativeDaemon);d.uncertain=False;d.processes=[]
        with patch.object(M.threading,'active_count',return_value=1),patch.object(M.signal,'SIGCHLD',17,create=True),\
             patch.object(M.signal,'getsignal',return_value=M.signal.SIG_DFL),patch.object(M.os,'pidfd_open',create=True),\
             patch.object(M.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaisesRegex(M.Unavailable,'daemon_timeout_reserve'):d.call(['inspect','a'*64],5,200,100)

    def test_foreign_reaper_or_thread_policy_refuses_before_launch(self):
        d=M.NativeDaemon.__new__(M.NativeDaemon);d.uncertain=False;d.processes=[]
        with patch.object(M.threading,'active_count',return_value=2),patch.object(M.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaisesRegex(M.Unavailable,'sole_reaper_required'):d.call(['inspect','a'*64],10,200,100)

    def test_guard_first_fstat_failure_keeps_registered_descriptor(self):
        guard=M.NativeFeedGuard();feed=inputs()[2]
        with patch.object(M.os,'O_DIRECTORY',0,create=True),patch.object(M.os,'O_NOFOLLOW',0,create=True),\
             patch.object(M.os,'open',return_value=52),patch.object(M.os,'fstat',side_effect=OSError('injected')),\
             patch.object(M.os,'close') as close:
            with self.assertRaises(OSError):guard.verify(feed,200)
            self.assertEqual(len(guard.directories),1);guard.close();close.assert_called_once_with(52)

    def test_journal_first_fstat_failure_tracks_and_attempts_close(self):
        journal=M.NativeJournal()
        with patch.object(M.os,'O_DIRECTORY',0,create=True),patch.object(M.os,'O_NOFOLLOW',0,create=True),\
             patch.object(M.os,'open',return_value=53),patch.object(M.os,'fstat',side_effect=OSError('injected')),\
             patch.object(M.os,'close') as close:
            with self.assertRaises(OSError):journal.hold_directory(Path('/fake'))
            with self.assertRaises(M.Unavailable):journal.close()
            close.assert_called_once_with(53);self.assertTrue(journal.uncertain)

    def test_journal_close_failure_preserves_exact_refs_and_attempts_all(self):
        journal=M.NativeJournal();state=fake_stat();first=Path('/first');second=Path('/second')
        journal.directories={first:(11,M.metadata(state)),second:(12,M.metadata(state))}
        journal.owned_files={42:'owned-first',43:'owned-second'};journal.command_fd=42;trace=[]
        def close(fd):
            trace.append(fd)
            if fd in (42,11):raise OSError('injected')
        with patch.object(M.os,'fstat',return_value=state),patch.object(M.Path,'lstat',return_value=state),patch.object(M.os,'close',side_effect=close):
            with self.assertRaisesRegex(M.Unavailable,'journal_release_unknown'):journal.close()
            with self.assertRaisesRegex(M.Unavailable,'journal_release_unknown'):journal.close()
        self.assertEqual(trace,[42,43,12,11]);self.assertEqual(journal.owned_files,{42:'owned-first'})
        self.assertEqual(set(journal.directories),{first});self.assertIsNone(journal.closed_views)

    def test_journal_directory_replacement_refuses_before_file_create(self):
        journal=M.NativeJournal();path=Path('/root');before=fake_stat();journal.root=path
        journal.directories={path:(11,M.metadata(before))}
        with patch.object(M.os,'fstat',return_value=before),patch.object(M.Path,'lstat',return_value=fake_stat(st_ino=99)),\
             patch.object(M.os,'open',side_effect=AssertionError('write')):
            with self.assertRaisesRegex(M.Unavailable,'journal_directory_drift'):journal.put('result.json',b'{}')

    def test_journal_permission_drift_cannot_be_refreshed(self):
        journal=M.NativeJournal();path=Path('/root');before=fake_stat();changed=fake_stat(st_mode=M.stat.S_IFDIR|0o777)
        journal.directories={path:(11,M.metadata(before))}
        with patch.object(M.os,'fstat',return_value=changed),patch.object(M.Path,'lstat',return_value=changed):
            with self.assertRaisesRegex(M.Unavailable,'journal_directory_drift'):journal.refresh(path)

    def test_mountinfo_exact_encrypted_source_device_and_longest_cover(self):
        raw=b'1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 253:0 / /srv/autosoft rw - xfs /dev/mapper/autosoft-data rw\n'
        self.assertEqual(M.encrypted_mount(raw,'/srv/autosoft/validation',(253,0)),'/dev/mapper/autosoft-data')
        for altered,device in ((raw.replace(b'autosoft-data',b'foreign'),(253,0)),(raw,(253,1)),
              (raw+raw.splitlines(keepends=True)[1],(253,0)),
              (raw+b'3 2 8:2 / /srv/autosoft/validation rw - ext4 /dev/sdb1 rw\n',(253,0)),
              (b'malformed\n',(253,0)),(b'x'*65537,(253,0))):
            with self.assertRaises(M.Unavailable):M.encrypted_mount(altered,'/srv/autosoft/validation',device)

    def test_nested_boolean_resource_alias_and_oom_numeric_denied(self):
        s,c,f,i=inputs();spec=M.request(s,c,f,'fixed',i[0]['Config']['Env'],ID,M.selected_manifest(i[0]));identifier='1'*64
        for variant in ('retry','oom'):
            value=inspection(identifier,spec)
            if variant=='retry':value['HostConfig']['RestartPolicy']['MaximumRetryCount']=False
            else:value['HostConfig']['OomKillDisable']=0
            with self.assertRaises(M.Unavailable):M.inspect_owned(M.canonical([value]),identifier,spec)

    def test_retained_metadata_timestamps_must_match_content(self):
        expected=inputs()[2]['timestamps'];M.metadata_timestamps(M.canonical(expected),expected)
        for key,value in (('Version',True),('NextUpdate','2026-10-13T01:00:00Z'),('UpdatedAt','2026-10-12T01:00:00Z')):
            changed=dict(expected);changed[key]=value
            with self.assertRaisesRegex(M.Unavailable,'metadata_timestamps_binding'):
                M.metadata_timestamps(M.canonical(changed),expected)
        with self.assertRaises(M.Unavailable):M.metadata_timestamps(M.canonical(dict(expected,extra='denied')),expected)

    def test_native_process_creation_failure_is_not_a_result(self):
        d=M.NativeDaemon.__new__(M.NativeDaemon);d.uncertain=False;d.processes=[];d.socket_fd=8;d.socket=M.metadata(fake_stat());d.config='/fixed/config'
        with patch.object(M.threading,'active_count',return_value=1),patch.object(M.signal,'SIGCHLD',17,create=True),\
             patch.object(M.signal,'getsignal',return_value=M.signal.SIG_DFL),patch.object(M.os,'pidfd_open',create=True),\
             patch.object(M.os,'fstat',return_value=fake_stat()),patch.object(M.Path,'lstat',return_value=fake_stat()),\
             patch.object(M.subprocess,'Popen',side_effect=OSError('injected')):
            with self.assertRaises(OSError):d.call(['create','fixed'],10,200,100)
        self.assertEqual(d.processes,[])

    def test_daemon_constructor_failure_closes_or_preserves_socket_owner(self):
        class ConstructorPath:
            def __init__(self,value):self.value=str(value)
            def __truediv__(self,value):return ConstructorPath(self.value+'/'+value)
            def __str__(self):return self.value
            def lstat(self):raise OSError('injected')
        original=list(M.UNCERTAIN_NATIVE_OWNERS)
        try:
            for fail in (False,True):
                M.UNCERTAIN_NATIVE_OWNERS.clear()
                with patch.object(M.os,'name','posix'),patch.object(M.os,'geteuid',return_value=0,create=True),\
                     patch.object(M.os,'O_PATH',0,create=True),patch.object(M.os,'O_NOFOLLOW',0,create=True),\
                     patch.object(M.os,'open',return_value=57),patch.object(M,'Path',ConstructorPath),\
                     patch.object(M.os,'close',side_effect=OSError('injected') if fail else None) as close:
                    with self.assertRaises(OSError):M.NativeDaemon('/fixed/root')
                close.assert_called_once_with(57)
                if fail:self.assertEqual(M.UNCERTAIN_NATIVE_OWNERS[-1].socket_fd,57)
                else:self.assertEqual(M.UNCERTAIN_NATIVE_OWNERS,[])
        finally:M.UNCERTAIN_NATIVE_OWNERS[:]=original

    def test_guard_unknown_close_never_retries_or_reads_reusable_fd(self):
        guard=M.NativeFeedGuard();path=Path('/owned');guard.files[path]=(52,fake_stat())
        with patch.object(M.os,'close',side_effect=OSError('injected')) as close:
            for _ in range(2):
                with self.assertRaisesRegex(M.Unavailable,'feed_close_failed'):guard.close()
            with self.assertRaisesRegex(M.Unavailable,'feed_release_unknown'):guard.verify(inputs()[2],200)
        close.assert_called_once_with(52);self.assertIn(path,guard.files)

    def test_socket_unknown_close_never_retries_or_launches(self):
        d=M.NativeDaemon.__new__(M.NativeDaemon);d.socket_fd=57;d.processes=[];d.uncertain=False
        with patch.object(M.os,'close',side_effect=OSError('injected')) as close,patch.object(M.subprocess,'Popen',side_effect=AssertionError('launch')):
            with self.assertRaises(OSError):d.close()
            with self.assertRaisesRegex(M.Unavailable,'daemon_socket_release_unknown'):d.close()
            with self.assertRaisesRegex(M.Unavailable,'daemon_cleanup_unknown'):d.call(['inspect','a'*64],10,200,100)
        close.assert_called_once_with(57);self.assertEqual(d.socket_fd,57)

    def test_expiry_after_initial_hash_and_at_terminal_denies_success(self):
        for terminal in (False,True):
            q,s,c,f,d,j,g=Controls().make();original=g.verify
            def verify(*args,**kwargs):
                original(*args,**kwargs)
                if len(g.calls)==(5 if terminal else 1):q.utc=lambda:NOW+timedelta(days=1)
            g.verify=verify;r=q.run(s,c,f)
            self.assertEqual(r['status'],'unavailable');self.assertFalse(r['scopedReadOnlyLookupVerified']);self.assertTrue(q.pending)
            if terminal:self.assertEqual(d.created,3);self.assertFalse(d.containers)
            else:self.assertFalse(d.calls);self.assertIn('intent.json',j.records)

    def test_approved_inspection_with_extra_image_secret_env_never_creates(self):
        q,s,c,f,d,j,g=Controls().make();d.image[0]['Config']['Env'].append('TOKEN=untrusted-fixture-value')
        c['imageInspectSHA256']=M.digest(M.canonical(d.image));s['companyEvidence']=dict(sha256=M.digest(M.canonical(c)),bytes=len(M.canonical(c)))
        r=q.run(s,c,f);self.assertEqual(r['failureCode'],'image_environment');self.assertEqual(d.created,0)

    def test_sibling_once_creation_precedes_initial_guard_without_rebaseline(self):
        q,s,c,f,d,j,g=Controls().make();events=[];begin=j.begin;verify=g.verify
        def ordered_begin(*args):events.append('fresh-once-and-fixtures');begin(*args)
        def ordered_guard(*args,**kwargs):events.append('guard');verify(*args,**kwargs)
        j.begin=ordered_begin;g.verify=ordered_guard;r=q.run(s,c,f)
        self.assertEqual(events[:2],['fresh-once-and-fixtures','guard'])
        self.assertEqual(events.count('fresh-once-and-fixtures'),1);self.assertEqual(events.count('guard'),5)
        self.assertEqual(r['status'],'isolated_os_probe_verified');self.assertEqual(g.calls,[True,False,False,False,True])

    def test_resource_limits_do_not_inherit_small_address_space_cap_to_go_cli(self):
        calls=[];resource=SimpleNamespace(RLIMIT_AS=1,RLIMIT_CPU=2,RLIMIT_NOFILE=3,RLIMIT_CORE=4,RLIMIT_FSIZE=5,
            setrlimit=lambda kind,value:calls.append((kind,value)))
        M.native_limits(resource)
        self.assertEqual(calls,[(2,(120,120)),(3,(48,48)),(4,(0,0)),(5,(16*1024**2,16*1024**2))])
        self.assertFalse(any(kind==resource.RLIMIT_AS for kind,_ in calls))

    def test_terminal_reopened_resource_close_failure_clears_release_assertion(self):
        r,q,d,j,g=Controls().run_case(journal_fail='terminal-close')
        self.assertEqual(j.closed,1);self.assertEqual(g.closed,1);self.assertEqual(d.closed,1)
        self.assertEqual(j.terminal_unknown_refs,(70,71));self.assertFalse(d.containers)
        self.assertEqual(r['status'],'unavailable');self.assertEqual(r['failureCode'],'result_retention_failed')
        self.assertIs(r['ownedFilesReleased'],False);self.assertIs(r['scopedReadOnlyLookupVerified'],False)
        self.assertTrue(q.pending)


class MountRepresentationControls(unittest.TestCase):
    def fixture(self, bind_only=False):
        scope, company, feed, image = inputs()
        spec = M.request(scope, company, feed, 'version', image[0]['Config']['Env'], ID, M.selected_manifest(image[0]))
        value = copy.deepcopy(inspection('1'*64, spec))
        if bind_only: value['Mounts'] = value['Mounts'][:2]
        return spec, value

    def check(self, spec, value, baseline=None):
        return M.inspect_owned(M.canonical([value]), '1'*64, spec, baseline)

    def test_bind_only_actual_representation_retains_exact_host_tmpfs(self):
        spec, value = self.fixture(True)
        state, profile = self.check(spec, value)
        self.assertEqual(state['Status'], 'created'); self.assertEqual(len(profile), 64)
        self.assertEqual(value['HostConfig']['Tmpfs'], M.TMPFS)
        self.assertEqual({v['Destination'] for v in value['Mounts']}, {'/inventory', '/cache/trivy/db'})

    def test_reported_complete_tmpfs_pair_remains_accepted(self):
        spec, value = self.fixture()
        self.assertEqual(len(value['Mounts']), 4)
        self.check(spec, value)
        value['Mounts'].reverse()
        self.check(spec, value)

    def test_injected_lifecycle_with_two_bind_mounts_reaches_cleanup(self):
        original = inspection
        def bind_only(identifier, request):
            value = original(identifier, request)
            value['Mounts'] = value['Mounts'][:2]
            return value
        with patch.object(sys.modules[__name__], 'inspection', side_effect=bind_only):
            result, q, daemon, journal, guard = Controls().run_case()
        self.assertEqual(result['status'], 'isolated_os_probe_verified')
        self.assertTrue(result['cleanupConfirmed']); self.assertFalse(daemon.containers)
        self.assertEqual(daemon.created, 3); self.assertFalse(q.pending)
        self.assertFalse(result['nativeObserved'])

    def test_partial_tmpfs_and_missing_bind_sets_are_refused(self):
        spec, base = self.fixture()
        variants = [base['Mounts'][:3], base['Mounts'][1:], base['Mounts'][:1], [],
                    base['Mounts'][2:], [base['Mounts'][0], base['Mounts'][2]]]
        for mounts in variants:
            with self.subTest(mounts=mounts):
                value = copy.deepcopy(base); value['Mounts'] = copy.deepcopy(mounts)
                with self.assertRaisesRegex(M.Unavailable, 'container_mount'):
                    self.check(spec, value)

    def test_extra_unknown_and_duplicate_mounts_are_refused(self):
        spec, base = self.fixture()
        variants = [base['Mounts']+[dict(Type='tmpfs', Destination='/extra')],
                    base['Mounts'][:2]+[dict(Type='volume', Destination='/tmp'), base['Mounts'][3]],
                    base['Mounts'][:2]+[dict(Type='tmpfs', Destination='/foreign'), base['Mounts'][3]],
                    base['Mounts'][:2]+[base['Mounts'][2], base['Mounts'][2]],
                    [base['Mounts'][0], base['Mounts'][0]],
                    [base['Mounts'][0], dict(base['Mounts'][1], Destination=base['Mounts'][0]['Destination'])],
                    [base['Mounts'][0], dict(Type='tmpfs', Destination='/tmp')]]
        for mounts in variants:
            with self.subTest(mounts=mounts):
                value = copy.deepcopy(base); value['Mounts'] = copy.deepcopy(mounts)
                with self.assertRaisesRegex(M.Unavailable, 'container_mount|container_tmpfs'):
                    self.check(spec, value)

    def test_bind_safety_paths_and_destination_types_remain_strict(self):
        spec, base = self.fixture(True)
        for change in (dict(RW=True), dict(RW=0), dict(Propagation='rshared'),
                       dict(Source='/foreign'), dict(Destination='/foreign'),
                       dict(Destination=None), dict(Destination=[]), dict(Type='volume')):
            with self.subTest(change=change):
                value = copy.deepcopy(base); value['Mounts'][0].update(change)
                with self.assertRaisesRegex(M.Unavailable, 'container_mount|container_tmpfs|readonly_mount'):
                    self.check(spec, value)

    def test_exact_host_tmpfs_options_required_for_both_representations(self):
        for bind_only in (False, True):
            spec, base = self.fixture(bind_only)
            variants = [None, [], {}, {'/tmp': M.TMPFS['/tmp']}, dict(M.TMPFS, **{'/extra': 'size=1m'})]
            for target in M.TMPFS:
                options = M.TMPFS[target].split(',')
                for index in range(len(options)):
                    value = copy.deepcopy(M.TMPFS)
                    value[target] = ','.join(options[:index]+options[index+1:])
                    variants.append(value)
                value = copy.deepcopy(M.TMPFS); value[target] += ',rw'
                variants.append(value)
            for tmpfs in variants:
                with self.subTest(bind_only=bind_only, tmpfs=tmpfs):
                    value = copy.deepcopy(base); value['HostConfig']['Tmpfs'] = tmpfs
                    with self.assertRaisesRegex(M.Unavailable, 'container_resources'):
                        self.check(spec, value)

    def test_mount_representation_is_not_normalized_in_profile_continuity(self):
        spec, bind_only = self.fixture(True)
        _, baseline = self.check(spec, bind_only)
        self.check(spec, bind_only, baseline)
        _, complete = self.fixture()
        self.check(spec, complete)
        with self.assertRaisesRegex(M.Unavailable, 'container_profile_drift'):
            self.check(spec, complete, baseline)


class OomProfileControls(unittest.TestCase):
    def fixture(self):
        return MountRepresentationControls().fixture(True)

    def check(self, spec, value, baseline=None):
        return M.inspect_owned(M.canonical([value]), '1'*64, spec, baseline)

    def test_false_to_null_preserves_exact_profile_baseline(self):
        spec, value = self.fixture()
        _, baseline = self.check(spec, value)
        value['HostConfig']['OomKillDisable'] = None
        self.assertEqual(self.check(spec, value, baseline)[1], baseline)

    def test_null_to_false_preserves_exact_profile_baseline(self):
        spec, value = self.fixture()
        value['HostConfig']['OomKillDisable'] = None
        _, baseline = self.check(spec, value)
        value['HostConfig']['OomKillDisable'] = False
        self.assertEqual(self.check(spec, value, baseline)[1], baseline)

    def test_true_numeric_string_and_container_values_are_refused(self):
        spec, base = self.fixture()
        for invalid in (True, 0, 0.0, 1, 1.0, 'false', 'null', '', [], {}):
            with self.subTest(invalid=invalid):
                value = copy.deepcopy(base)
                value['HostConfig']['OomKillDisable'] = invalid
                with self.assertRaisesRegex(M.Unavailable, 'container_isolation'):
                    self.check(spec, value)

    def test_missing_oom_field_is_refused_before_profile_hash(self):
        spec, value = self.fixture()
        del value['HostConfig']['OomKillDisable']
        with self.assertRaisesRegex(M.Unavailable, 'container_isolation'):
            self.check(spec, value)

    def test_profile_copy_leaves_parsed_host_config_and_input_unchanged(self):
        spec, value = self.fixture()
        _, baseline = self.check(spec, value)
        value['HostConfig']['OomKillDisable'] = None
        original = copy.deepcopy(value)
        host = value['HostConfig']
        raw = M.canonical([value])
        with patch.object(M, 'parse', return_value=[value]) as parse:
            self.assertEqual(M.inspect_owned(raw, '1'*64, spec, baseline)[1], baseline)
        parse.assert_called_once_with(raw)
        self.assertIs(value['HostConfig'], host)
        self.assertIs(host['OomKillDisable'], None)
        self.assertEqual(value, original)
        self.assertEqual(raw, M.canonical([original]))

    def test_other_profile_drift_is_denied_with_oom_null(self):
        spec, base = self.fixture()
        _, baseline = self.check(spec, base)
        for field in ('host', 'config', 'mounts'):
            with self.subTest(field=field):
                value = copy.deepcopy(base)
                value['HostConfig']['OomKillDisable'] = None
                if field == 'host': value['HostConfig']['LogConfig']['Config'] = {'changed': '1'}
                elif field == 'config': value['Config']['Labels']['extra'] = 'changed'
                else: value['Mounts'].reverse()
                with self.assertRaisesRegex(M.Unavailable, 'container_profile_drift'):
                    self.check(spec, value, baseline)

    def test_injected_poststart_null_lifecycle_reaches_original_cleanup(self):
        q, scope, company, feed, daemon, journal, guard = Controls().make()
        original = daemon.call
        def call(args, *limits):
            result = original(args, *limits)
            if args[0] == 'start':
                daemon.containers[args[-1]][1]['HostConfig']['OomKillDisable'] = None
            return result
        daemon.call = call
        result = q.run(scope, company, feed)
        self.assertEqual(result['status'], 'isolated_os_probe_verified')
        self.assertTrue(result['cleanupConfirmed'])
        self.assertFalse(daemon.containers)
        self.assertEqual(daemon.created, 3)
        self.assertFalse(q.pending)
        self.assertFalse(result['nativeObserved'])


class TargetSeverityControls(unittest.TestCase):
    def test_medium_high_and_critical_exact_target_reports_are_accepted(self):
        for severity in ('MEDIUM', 'HIGH', 'CRITICAL'):
            with self.subTest(severity=severity):
                value = scanner_report('vulnerable')
                value['Results'][0]['Vulnerabilities'][0]['Severity'] = severity
                result = M.report(M.canonical(value), 'vulnerable')
                self.assertTrue(result['expectedAdvisoryPresent'])
                self.assertEqual(result['packageVersion'], M.VERSIONS['vulnerable'])
                self.assertEqual(result['otherFindings'], 0)

    def test_low_unknown_missing_nonstring_and_noncanonical_target_severity_are_refused(self):
        invalid = ('LOW', 'UNKNOWN', None, True, False, 0, 1, 3.5, [], {}, 'critical', 'high', 'medium', ' HIGH', 'MEDIUM\n', '')
        for severity in invalid:
            with self.subTest(severity=severity):
                value = scanner_report('vulnerable')
                value['Results'][0]['Vulnerabilities'][0]['Severity'] = severity
                with self.assertRaises(M.Unavailable):
                    M.report(M.canonical(value), 'vulnerable')
        value = scanner_report('vulnerable')
        del value['Results'][0]['Vulnerabilities'][0]['Severity']
        with self.assertRaises(M.Unavailable):
            M.report(M.canonical(value), 'vulnerable')

    def test_critical_severity_does_not_relax_any_exact_target_identity_field(self):
        mutations = (
            ('VulnerabilityID', 'CVE-2023-00000'), ('VulnerabilityID', None),
            ('PkgName', 'curl'), ('PkgName', None),
            ('InstalledVersion', M.VERSIONS['fixed']), ('InstalledVersion', None),
            ('FixedVersion', '7.88.1-10+deb12u5'), ('FixedVersion', None),
            ('DataSource', {'ID': 'foreign'}), ('DataSource', {}), ('DataSource', None), ('DataSource', 'debian')
        )
        for field, changed in mutations:
            with self.subTest(field=field, changed=changed):
                value = scanner_report('vulnerable')
                target = value['Results'][0]['Vulnerabilities'][0]
                target['Severity'] = 'CRITICAL'; target[field] = changed
                with self.assertRaises(M.Unavailable):
                    M.report(M.canonical(value), 'vulnerable')

    def test_all_eligible_severities_keep_exact_positive_count_and_fixed_negative_boundary(self):
        for severity in ('MEDIUM', 'HIGH', 'CRITICAL'):
            with self.subTest(severity=severity):
                value = scanner_report('vulnerable')
                target = value['Results'][0]['Vulnerabilities'][0]; target['Severity'] = severity
                value['Results'][0]['Vulnerabilities'].append(copy.deepcopy(target))
                with self.assertRaisesRegex(M.Unavailable, 'advisory_boundary'):
                    M.report(M.canonical(value), 'vulnerable')
                fixed = scanner_report('fixed')
                target = copy.deepcopy(target); target['InstalledVersion'] = M.VERSIONS['fixed']
                fixed['Results'][0]['Vulnerabilities'] = [target]
                with self.assertRaisesRegex(M.Unavailable, 'advisory_boundary'):
                    M.report(M.canonical(fixed), 'fixed')

    def test_injected_critical_workflow_reaches_fixed_case_and_only_scoped_success(self):
        q, scope, company, feed, daemon, journal, guard = Controls().make()
        original = scanner_report
        def positive(case):
            value = original(case)
            if case == 'vulnerable': value['Results'][0]['Vulnerabilities'][0]['Severity'] = 'CRITICAL'
            return value
        with patch.dict(Daemon.call.__globals__, {'scanner_report': positive}):
            result = q.run(scope, company, feed)
        self.assertEqual(result['status'], 'isolated_os_probe_verified')
        self.assertEqual([value['case'] for value in result['cases']], ['vulnerable', 'fixed'])
        self.assertTrue(result['cases'][0]['expectedAdvisoryPresent'])
        self.assertFalse(result['cases'][1]['expectedAdvisoryPresent'])
        self.assertTrue(result['scopedReadOnlyLookupVerified'])
        self.assertIn('created-fixed.json', journal.records)
        self.assertEqual(daemon.created, 3); self.assertFalse(daemon.containers); self.assertFalse(q.pending)
        self.assertTrue(result['cleanupConfirmed']); self.assertTrue(result['originalFeedPreserved']); self.assertTrue(result['ownedFilesReleased'])
        for field in ('nativeObserved', 'companySecurityEligible', 'nativeImageScannerQualified', 'globalDailyFeedQualified', 'productionQualified', 'automaticRetry'):
            self.assertIs(result[field], False)
        self.assertEqual(result['promotionActions'], 0); self.assertEqual(result['serviceMutations'], 0)

    def test_injected_low_and_unknown_workflows_refuse_before_fixed_fixture(self):
        original = scanner_report
        for severity in ('LOW', 'UNKNOWN'):
            with self.subTest(severity=severity):
                q, scope, company, feed, daemon, journal, guard = Controls().make()
                def positive(case):
                    value = original(case)
                    if case == 'vulnerable': value['Results'][0]['Vulnerabilities'][0]['Severity'] = severity
                    return value
                with patch.dict(Daemon.call.__globals__, {'scanner_report': positive}):
                    result = q.run(scope, company, feed)
                self.assertEqual(result['status'], 'unavailable'); self.assertEqual(result['failureCode'], 'expected_advisory')
                self.assertNotIn('create-intent-fixed.json', journal.records); self.assertNotIn('created-fixed.json', journal.records)
                self.assertEqual(daemon.created, 2); self.assertFalse(daemon.containers); self.assertTrue(q.pending)
                self.assertEqual(result['cases'], []); self.assertFalse(result['scopedReadOnlyLookupVerified'])
                self.assertFalse(result['nativeImageScannerQualified']); self.assertFalse(result['globalDailyFeedQualified']); self.assertFalse(result['productionQualified'])


if __name__ == '__main__': unittest.main(verbosity=2)

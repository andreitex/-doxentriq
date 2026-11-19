"""Real catalog/FD checks joined to original synthetic foundation/consumer authority fixtures.

No cryptographic authentication, package installation or host foundation is claimed here.
"""
import copy,importlib.util,json,os,sys,unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('engine_handoff_fixture',ROOT/'tests/test_company_engine_native.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
W,H,E,C,V=F.W,F.H,F.E,F.C,F.V

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root protected file fixtures')
class HandoffTests(unittest.TestCase):
    @contextmanager
    def harness(self):
        with F.NativeTests().mapped() as x:
            h=V.F.Harness();calls=[]
            def run(argv,timeout):
                if argv[0]=='/bin/bash':
                    phase=next(n for n in ('packages_v2','storage','prepare','activate') if argv[4].endswith('company_'+n+'_phase "$@"\n'))
                    h.events.append(('phase',phase,argv,timeout))
                    if h.phase_fail==phase:raise ValueError('company phase outcome unknown')
                    return b''
                calls.append(tuple(argv));key=next(key for key in x.replies if tuple(argv[:len(key)])==key);return x.replies[key]
            h.modules.update({'company_native_station.py':x.station,'company_host_package_runtime.py':H,'company_engine_packages.py':C,'company_engine_native.py':E,'company_engine_elf.py':F.ELF})
            h.runner=SimpleNamespace(run=run)
            with patch.object(W,'COMPANY_FINGERPRINT',V.F.FP),patch.object(W,'measure',h.measure),patch.object(W,'host_bindings',return_value=(x.p,x.t)):
                def execute(verify=False):return W.Worker(h.modules,h.state,h.runner,output_guard=h.output_guard,host_catalogs={'engine':F.encoded(x.f.raw)}).run(V.F.request(),object(),verify=verify)
                yield x,h,calls,execute
    def test_company_execute_and_separate_verifier_use_exact_actual_readback(self):
        with self.harness() as (x,h,calls,execute):
            first=execute();self.assertEqual(first['schemaVersion'],2);self.assertEqual(first['hostPackages']['schemaVersion'],2);self.assertEqual(len(first['hostPackages']['installedExecutablePins']),8)
            phases=[row for row in h.events if isinstance(row,tuple) and row[0]=='phase'];self.assertEqual([row[1] for row in phases],['packages_v2','storage','prepare','activate']);self.assertEqual(len(phases[0][2]),23)
            self.assertIn('DOXENTRIQ_ENGINE_MANIFESTS=',phases[0][2][4]);self.assertLessEqual(len(phases[0][2][4].encode()),65536)
            self.assertEqual(execute(True),first);self.assertEqual(sum(argv[0]=='/usr/bin/rpm' for argv in calls),3)
            self.assertTrue(any(path.endswith('/verified') for path in h.state.records))
    def test_unknown_company_phase_keeps_intent_and_never_queries_or_retries(self):
        with self.harness() as (x,h,calls,execute):
            h.phase_fail='packages_v2'
            with self.assertRaisesRegex(ValueError,'outcome unknown'):execute()
            self.assertEqual(calls,[]);self.assertEqual(len([row for row in h.events if isinstance(row,tuple) and row[0]=='phase']),1)
            self.assertTrue(any(path.endswith('/intent.json') for path in h.state.records));self.assertFalse(any(path.endswith('/result.json') for path in h.state.records))
    def test_bad_current_company_package_blocks_storage(self):
        with self.harness() as (x,h,calls,execute):
            x.replies[('/usr/bin/rpm','-q')]=x.replies[('/usr/bin/rpm','-q')].replace(b'29.9.3',b'29.9.4')
            with self.assertRaises(ValueError):execute()
            self.assertEqual([row[1] for row in h.events if isinstance(row,tuple) and row[0]=='phase'],['packages_v2']);self.assertFalse(any(path.endswith('/result.json') for path in h.state.records))
    def test_support_file_change_after_effects_prevents_separate_confirmation(self):
        with self.harness() as (x,h,calls,execute):
            execute();(x.root/'usr/lib/systemd/system/docker.socket').write_bytes(b'changed privileged socket')
            with self.assertRaises(ValueError):execute(True)
            self.assertFalse(any(path.endswith('/verified') for path in h.state.records))
    def test_configuration_consumer_joins_own_company_catalog_and_current_readback(self):
        with F.NativeTests().mapped() as x:
            current=x.readback();r=V.F.request();request=dict(r,mode='full');events=[]
            previous=SimpleNamespace(sources={'scripts/install.sh':b'authenticated fixture phase'},templates={},configs={'catalog.json':b'{}'},provenance={},metadata={'releaseSha256':r['releaseSha256']},recheck=lambda:events.append('source-check'))
            held=SimpleNamespace(files=dict(previous.sources),configs=dict(previous.configs))
            rows=dict(previous.sources);rows.update({'company-release/'+name:raw for name,raw in previous.configs.items()})
            tree=H.sha(H.canonical({name:dict(bytes=len(raw),sha256=H.sha(raw)) for name,raw in sorted(rows.items())}))
            host={'installation.intent.json':{},'installation.json':{'installation_id':'synthetic'},'installation.storage-receipt.json':{}}
            result=dict(schemaVersion=2,hostPackages=current,scope='FOUNDATION_ONLY',status='effects-independently-confirmed',operationId=r['operationId'],installationId='synthetic',releaseSha256=r['releaseSha256'],treeSha256=tree,hostSha256=H.sha(H.canonical(host)),runscVersionSha256='a'*64,runtimeBinaryPins={},fullPlatformActivated=False,backupReady=False,runtimePairInitialized=False)
            evidence='/opt/autosoft-company/evidence/'+r['operationId'];store={evidence+'/intent.json':H.canonical(r),evidence+'/result.json':H.canonical(result)}
            def marker():store[evidence+'/verified']=('foundation-verified-v1\noperation='+r['operationId']+'\noutcome='+H.sha(store[evidence+'/result.json'])+'\n').encode()
            marker();store.update({'/etc/autosoft/'+name:H.canonical(value) for name,value in host.items()})
            @contextmanager
            def authenticate(*args,**kw):events.append('source-enter');yield previous;events.append('source-close')
            verifier=SimpleNamespace(authenticated_deployment=authenticate,require_platform_source=lambda _:None)
            def consume(observed):
                with patch.object(V.C,'host_observation',return_value=(H,x.p,x.t,observed)):
                    return V.C.foundation(V.Q,SimpleNamespace(read_protected=lambda p,n:store[p]),verifier,request,held,{'files':None,'crypto':None},'a'*64,modules={'engine_native':E},host_catalogs={'engine':F.encoded(x.f.raw)},check_authority=lambda:None)
            self.assertEqual(len(consume(current)),64);self.assertIn('source-close',events)
            changed=copy.deepcopy(current);changed['packageProfileSha256']='f'*64
            with self.assertRaises(ValueError):consume(changed)
            # Self-consistent receipts from a foreign catalog still fail own binding.
            result['hostPackages']=changed;store[evidence+'/result.json']=H.canonical(result);marker()
            with self.assertRaises(ValueError):consume(changed)
            # A legacy/unpinned result is readable evidence, never new authority.
            result.pop('schemaVersion');result.pop('hostPackages');store[evidence+'/result.json']=H.canonical(result);marker()
            with self.assertRaisesRegex(ValueError,'legacy records'):consume(current)

if __name__=='__main__':unittest.main(verbosity=2)

"""Original Bash phase in private mount namespace; all package/service/policy effects are stubs.

Actual protected archive hashing and Bash ordering run. The phase payload callback is
explicitly synthetic; independent native FD payload coverage is in test_company_engine_native.
"""
import hashlib,importlib.util,json,os,shlex,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('engine_phase_fixture',ROOT/'tests/test_company_engine_native.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
STUBS=r'''
die() { printf '%s\n' "$*" >&2; exit 74; }
event() { printf '%s\n' "$*" >> "$FIXTURE/events"; }
company_context() { ID=rocky; VERSION_ID=10.2; if [[ "$CASE" = debian ]]; then ID=debian; VERSION_ID=13; fi; }
systemctl() { event systemctl; return 1; }
prepare_runtime_gate() { event gate; }
stop_gated_runtime_units() { event stopped; }
dnf() { if [[ "$*" = *localpkg_gpgcheck* ]]; then event company-install; else event distro-prerequisites; fi; }
rpm() {
  if [[ "$1" = -q ]]; then return 1; fi
  if [[ "$1" = -qp && "$2" = --queryformat ]]; then
    if [[ "$3" = *'PREUNTRANS?'* ]]; then event forbidden-metadata; if [[ "$CASE" = hidden-script ]]; then printf 'TRANSFILETRIGGERSCRIPTPROG\n'; fi; return 0; fi
    event payload-inventory
    local file=${*: -1} name=''; name=${file##*/}; name=${name%.rpm}
    cat "$FIXTURE/$name.metadata"
    if [[ "$CASE" = extra-file ]]; then printf '/etc/foreign\t12\t%s\t100644\troot\troot\t\t0\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; fi
    return 0
  fi
  if [[ "$1" = -qp ]]; then event script-inventory; if [[ "$CASE" = scripts ]]; then printf 'postinstall script\n'; fi; return 0; fi
  if [[ "$1" = --import ]]; then event global-key-import; return 0; fi
  if [[ "$3" = --initdb ]]; then event private-db; return 0; fi
  if [[ "$3" = --import ]]; then event private-key-import; return 0; fi
  if [[ "$3" = --checksig ]]; then event signature; if [[ "$CASE" = signature ]]; then printf 'RSA Signature: NOKEY\n'; else printf 'RSA/SHA256 Signature: OK\n'; fi; return 0; fi
  die unexpected-rpm
}
gpg() { event fingerprint; printf 'pub:::::::::\n'; if [[ "$CASE" = wrong-key ]]; then printf 'fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n'; else printf 'fpr:::::::::%s:\n' "$DOXENTRIQ_ENGINE_KEY_FINGERPRINT"; fi; }
getent() {
  case "$1" in
    group) if [[ "$CASE" = member ]]; then printf 'docker:x:987:alice\n'; elif [[ -e "$FIXTURE/group" ]]; then printf 'docker:x:987:\n'; else return 2; fi ;;
    passwd) printf 'root:x:0:0:root:/root:/bin/bash\n' ;;
    gshadow) printf 'docker:!::\n' ;;
    *) die unexpected-getent ;;
  esac
}
groupadd() { [[ "$*" = '--system docker' ]] || die unexpected-groupadd; event group-created; : > "$FIXTURE/group"; }
company_engine_payload_check() { event payload; [[ "$CASE" != payload ]] || die changed-installed-payload; }
getenforce() { printf 'Enforcing\n'; }
semodule() {
  if [[ "$1" = -i ]]; then event "policy:$2"; [[ "$CASE" != policy ]] || return 1
  elif [[ "$1" = -lfull ]]; then printf '400 docker-af-alg-deny cil\n400 docker-af-vsock-deny cil\n'
  else die unexpected-semodule; fi
}
restorecon() { event relabel; }
matchpathcon() { event labels-verified; }
'''
def child(base,case):
    assert os.geteuid()==0 and Path(base).is_absolute()
    root=Path(base)
    for name,target in [('etc','/etc'),('opt','/opt'),('run','/run'),('var','/var')]:
        subprocess.run(['/usr/bin/mount','--bind',str(root/name),target],check=True,timeout=10)
    script=(ROOT/'scripts/install.sh').read_text()
    # Keep original function bodies; override only trusted-effect collaborators.
    definitions=script[script.index('company_engine_archive_check() {'):script.index('company_storage_phase() {')]
    request=json.loads((root/'request.json').read_text())
    program='set -Eeuo pipefail\numask 077\n'+definitions+'\n'+STUBS+'\n'
    program+='FIXTURE='+shlex.quote(str(root))+'\nCASE='+shlex.quote(case)+'\n'
    program+='DOXENTRIQ_ENGINE_KEY_FINGERPRINT='+shlex.quote(request['fingerprint'])+'\nDOXENTRIQ_ENGINE_MANIFESTS='+shlex.quote(json.dumps(request['manifests']))+'\nDOXENTRIQ_ENGINE_PAYLOAD=synthetic-tested-separately\ncompany_packages_v2_phase "$@"\n'
    result=subprocess.run(['/bin/bash','--noprofile','--norc','-c',program,'fixture',*(['context']*7),*request['args']],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LC_ALL':'C'},timeout=20)
    print(json.dumps(dict(exitCode=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode(),events=(root/'events').read_text().splitlines() if (root/'events').exists() else [])))
    return 0

@unittest.skipUnless(sys.platform=='linux' and getattr(os,'geteuid',lambda:-1)()==0,'Linux root mount namespace fixture')
class PhaseTests(unittest.TestCase):
    def phase(self,case):
        with tempfile.TemporaryDirectory(prefix='doxentriq-engine-phase-',dir=os.environ.get('DOXENTRIQ_NATIVE_TEST_ROOT','/root')) as directory:
            root=Path(directory);root.chmod(0o700)
            for name in ('etc','opt','run','var'):(root/name).mkdir(mode=0o755)
            (root/'etc/alternatives').mkdir();(root/'etc/alternatives/awk').symlink_to(Path('/usr/bin/awk').resolve())
            f=F.fixture();p,_=F.bound(f)
            for item in p['artifacts']:
                path=root/item['path'].lstrip('/');path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(f.archives[item['filename']]);path.chmod(0o400)
            if case=='tamper':(root/p['artifacts'][0]['path'].lstrip('/')).write_bytes(b'tampered archive')
            manifests=[json.loads(f.manifests[item['name']]) for item in p['source']['packages']]
            for manifest in manifests:
                item=manifest['package'];rows=manifest['files'];raw=item['name']+'\t0:'+item['version']+'\t'+item['architecture']+'\t8\n'
                raw+=''.join(row['path']+'\t'+str(row['bytes'])+'\t'+row['sha256']+'\t'+format(0o100000|row['mode'],'o')+'\troot\troot\t\t'+('128' if row['path'].startswith('/usr/share/licenses/') else '0')+'\t1\t'+str(index+1)+'\n' for index,row in enumerate(rows))
                if case=='hardlink':raw=raw.replace('\t1\t2\n','\t1\t1\n')
                if case=='ghost':raw=raw.replace('\t\t0\t','\t\t64\t')
                if case=='symlink':raw=raw.replace('\t100755\t','\t120777\t')
                (root/(item['name']+'.metadata')).write_text(raw)
            (root/'request.json').write_text(json.dumps(dict(args=list(p['shellArguments']),fingerprint=p['source']['packageSigningKey']['fingerprint'],manifests=manifests)))
            before=Path('/proc/self/mountinfo').read_bytes()
            result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--child',str(root),case],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LC_ALL':'C'},timeout=40)
            self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(Path('/proc/self/mountinfo').read_bytes(),before)
            return json.loads(result.stdout)
    def test_success_checks_payload_before_exact_policies_and_keeps_runtime_gated(self):
        r=self.phase('success');self.assertEqual(r['exitCode'],0,r['stderr']);events=r['events']
        self.assertLess(events.index('fingerprint'),events.index('private-key-import'));self.assertLess(events.index('signature'),events.index('global-key-import'));self.assertLess(events.index('company-install'),events.index('payload'))
        policies=[x for x in events if x.startswith('policy:')];self.assertEqual(policies,['policy:/usr/share/doxentriq-engine/selinux/docker-af-alg-deny.cil','policy:/usr/share/doxentriq-engine/selinux/docker-af-vsock-deny.cil'])
        self.assertEqual(events.count('payload-inventory'),4);self.assertLess(events.index('payload-inventory'),events.index('global-key-import'))
        self.assertLess(events.index('payload'),events.index(policies[0]));self.assertEqual(events.count('payload'),2);self.assertEqual(events[-1],'stopped');self.assertIn('labels-verified',events)
    def test_wrong_key_stops_before_any_rpm_key_import_or_company_install(self):
        r=self.phase('wrong-key');self.assertNotEqual(r['exitCode'],0);self.assertIn('distro-prerequisites',r['events']);self.assertNotIn('private-db',r['events']);self.assertNotIn('global-key-import',r['events']);self.assertNotIn('company-install',r['events'])
    def test_altered_archive_stops_before_gate_or_prerequisites(self):
        r=self.phase('tamper');self.assertNotEqual(r['exitCode'],0);self.assertEqual(r['events'],[])
    def test_existing_member_is_not_cleared_or_adopted(self):
        r=self.phase('member');self.assertNotEqual(r['exitCode'],0);self.assertNotIn('gate',r['events']);self.assertNotIn('group-created',r['events'])
    def test_company_debian_stops_before_all_stubs(self):
        r=self.phase('debian');self.assertNotEqual(r['exitCode'],0);self.assertEqual(r['events'],[])
    def test_unsigned_package_or_script_inventory_blocks_install(self):
        for case in ('signature','scripts'):
            r=self.phase(case);self.assertNotEqual(r['exitCode'],0);self.assertIn('signature',r['events']);self.assertNotIn('global-key-import',r['events']);self.assertNotIn('company-install',r['events'])
    def test_extra_rpm_file_blocks_before_global_import_or_install(self):
        r=self.phase('extra-file');self.assertNotEqual(r['exitCode'],0);self.assertIn('payload-inventory',r['events']);self.assertNotIn('global-key-import',r['events']);self.assertNotIn('company-install',r['events'])
    def test_undeclared_transaction_script_program_blocks_install(self):
        r=self.phase('hidden-script');self.assertNotEqual(r['exitCode'],0);self.assertIn('forbidden-metadata',r['events']);self.assertNotIn('payload-inventory',r['events']);self.assertNotIn('global-key-import',r['events'])
    def test_header_hardlink_ghost_and_symlink_are_rejected_before_install(self):
        for case in ('hardlink','ghost','symlink'):
            r=self.phase(case);self.assertNotEqual(r['exitCode'],0);self.assertIn('payload-inventory',r['events']);self.assertNotIn('global-key-import',r['events']);self.assertNotIn('company-install',r['events'])
    def test_payload_mismatch_never_loads_policy(self):
        r=self.phase('payload');self.assertNotEqual(r['exitCode'],0);self.assertIn('company-install',r['events']);self.assertFalse(any(x.startswith('policy:') for x in r['events']))
    def test_policy_failure_never_reaches_success_or_relabels(self):
        r=self.phase('policy');self.assertNotEqual(r['exitCode'],0);self.assertNotIn('relabel',r['events']);self.assertNotIn('stopped',r['events']);self.assertIn('policy:/usr/share/doxentriq-engine/selinux/docker-af-alg-deny.cil',r['events'])
if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--child':sys.exit(child(sys.argv[2],sys.argv[3]))
    unittest.main(verbosity=2)

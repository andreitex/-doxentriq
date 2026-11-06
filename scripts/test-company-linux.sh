#!/usr/bin/env bash
# Company code only; generated application code never uses this pipeline.
set -Eeuo pipefail
umask 077
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
require_root
load_installation
verify_runtime_storage
[[ ! -f /etc/autosoft/installation.complete ]] || die 'Use a company CI/test foundation, not an accepted customer production installation.'
SOURCE_ROOT=$(realpath -e -- "${1:?Usage: test-company-linux.sh STAGED_SOURCE GO_IMAGE_DIGEST}")
GO_IMAGE=${2:?Immutable Go 1.27.3 image required}
[[ "$SOURCE_ROOT" = "$DATA_DIR/validation/"* && -f "$SOURCE_ROOT/services/runtime/go.mod" && ! -L "$SOURCE_ROOT" ]] || die 'Company source must be a new encrypted validation directory.'
[[ "$GO_IMAGE" =~ ^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$ ]] || die 'Immutable Go image required.'
SOURCE_MANIFEST=${3:-${SOURCE_ROOT}.manifest.json}
[[ -f "$SOURCE_MANIFEST" ]] || die 'The verified source snapshot manifest is required.'
python3 - "$SOURCE_ROOT" "$SOURCE_MANIFEST" <<'PY'
import hashlib,json,pathlib,sys
source,proof=map(pathlib.Path,sys.argv[1:])
manifest=json.loads(proof.read_text())
actual={str(path.relative_to(source)):hashlib.sha256(path.read_bytes()).hexdigest() for path in source.rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix!='.pyc'}
if actual!=manifest['files']: raise SystemExit('Company test source differs from its verified file manifest')
print('Company source matches the verified per-file manifest')
PY
FIXTURE=$(mktemp -d "$DATA_DIR/validation/go-test-XXXXXXXX")
install -d -o 10001 -g 10001 -m 0750 "$FIXTURE/modules"
common=(run --rm --runtime=runsc --read-only --user=10001:10001 --cap-drop=ALL --security-opt=no-new-privileges --memory=2g --pids-limit=256 --tmpfs /tmp:exec,size=1g,mode=1777 --env HOME=/tmp --env GOTOOLCHAIN=local --env GOFLAGS=-mod=readonly --env GOMODCACHE=/modules --env GOCACHE=/tmp/cache --workdir /source/services/runtime --volume "$SOURCE_ROOT:/source:ro,z")
# Download trusted, checksum-locked company dependencies without running package scripts.
docker "${common[@]}" --network=bridge --volume "$FIXTURE/modules:/modules:z" "$GO_IMAGE" /bin/sh -c 'test "$(go env GOVERSION)" = go1.27.3 && go mod download'
# The actual company tests execute offline, with no host socket, credentials or writable source.
docker "${common[@]}" --network=none --volume "$FIXTURE/modules:/modules:ro,z" --env GOPROXY=off "$GO_IMAGE" go test -json -count=1 ./... > "$FIXTURE/go-tests.jsonl"
docker "${common[@]}" --network=none --volume "$FIXTURE/modules:/modules:ro,z" --env GOPROXY=off "$GO_IMAGE" go vet ./...
for file in "$SOURCE_ROOT"/scripts/*.sh; do bash -n "$file"; done
python3 - "$SOURCE_ROOT" <<'PY'
import ast,pathlib,sys
for source in (pathlib.Path(sys.argv[1])/'scripts').glob('*.py'): ast.parse(source.read_text())
print('Linux shell and Python syntax checks passed')
PY
python3 - "$SOURCE_ROOT" "$FIXTURE" <<'PY'
import hashlib,importlib.util,json,os,pathlib,sys,unittest
source,folder=map(pathlib.Path,sys.argv[1:])
sys.path.insert(0,str(source/'scripts'))
reports=[]
names=['scripts/'+name for name in ('test-deployment.py','test-install-runtime-gate.py','test-quota-helper.py','test-quota-startup.py','test-host-remediation.py','test-host-queries.py','test-host-kernel-security.py','test-host-package-inventory.py','test-maintenance-scanner.py','test-maintenance-scanner-diagnostics.py','test-maintenance-scanner-image-memory.py','test-maintenance-scanner-coverage.py','test-maintenance-image-export.py','test-maintenance-broker-security.py','test-registry-manifest.py','test-logging.py','test-pki.py','test-samba.py','test-recovery-tools.py','test-recovery-services.py','test-backup-quiescence.py','test-backup-recovery.py','test-recovery-chain.py','test-identity.py')]
names.append('deploy/connectors/test-filesystem.py')
names.append('test/test_checkpoint_admission.py')
names.append('scripts/test-quota-admission.py')
names.extend(('scripts/test-quota-command.py','scripts/test-runtime-layout.py','scripts/test-installation-identity.py'))
names.extend(('scripts/test-installation-wiring.py','scripts/test-installation-budgets.py','scripts/test-install-lock.py'))
names.append('scripts/test-installation-status.py')
names.append('scripts/test-host-network.py')
names.append('tests/test_identity_provisioning.py')
names.extend(('scripts/test-startup-binding.py','scripts/test-runtime-pair-init.py','scripts/test-install-lock-verification.py'))
names.extend(('scripts/test-installer-parent.py','scripts/test-recovery-catalog.py'))
names.append('scripts/test-company-source.py')
names.extend(('scripts/test-company-release.py','scripts/test-qualify-trivy-feed.py'))
names.append('tests/test_installer_materialize.py')
names.append('tests/test_company_foundation.py')
names.append('tests/test_company_runtime_identity.py')
names.extend(('tests/test_platform_source.py','tests/test_company_release_schema4.py','tests/test_company_platform_issuance.py','tests/test_authenticated_seed.py','tests/test_company_platform_store.py','tests/test_platform_git_runner.py','tests/test_install_session_stage_binding.py','tests/test_company_stored_platform_source.py','tests/test_company_source_tree.py'))
names.extend(('tests/test_company_source_guard.py', 'tests/test_company_source_guard_backend.py', 'tests/test_company_captured_loader.py', 'tests/test_company_full_entry.py'))
names.append('tests/test_company_stored_startup.py')
names.append('tests/test_company_fresh_assembly.py')
names.append('tests/test_platform_foundation_materialize.py')
names.extend(('tests/test_company_full_plan.py', 'tests/test_company_full_package.py', 'tests/test_company_full_package_loader.py', 'tests/test_company_runtime_pair_parent.py'))
names.extend(('tests/test_company_full_package_emit.py', 'tests/test_company_stage_scope.py'))
names.append('tests/test_company_full_retention_worker.py')
names.extend(('tests/test_company_parent_system.py', 'tests/test_company_seed_backend.py', 'tests/test_company_seed_runner.py', 'tests/test_company_retention_effects.py'))
names.append('tests/test_company_full_cli_package.py')
names.append('tests/test_company_full_cli.py')
names.append('tests/test_company_release_crypto.py')
cli_helper_tests=('tests/test_company_cli_record.py', 'tests/test_company_live_completion_receiver.py', 'tests/test_company_cli_live_verify_caller.py', 'tests/test_company_cli_executed_record_store.py', 'tests/test_company_bash_execution_status.py', 'tests/test_company_cli_verify_invocation.py', 'tests/test_company_cli_execute_bootstrap.py', 'tests/test_company_authenticated_cli_inputs.py', 'tests/test_company_authenticated_cli_compose.py', 'tests/test_company_binary_capture.py', 'tests/test_company_cli_record_io.py', 'tests/test_company_cli_record_publish.py', 'tests/test_company_cli_captured_publish.py', 'tests/test_company_cli_stage_child.py', 'tests/test_company_signed_execute_preparation.py', 'tests/test_company_fixed_execute_child.py', 'tests/test_company_startup_join.py')
names.extend(cli_helper_tests)
names.append('tests/test_provider_preflight.py')
names.append('tests/test_bootstrap_render_hooks.py')
names.append('tests/test_model_test_budget.py')
names.append('tests/test_model_budget_handover.py')
names.append('tests/test_public_npm_advisories.py')
names.append('tests/test_platform_recheck_efficiency.py')
names.append('tests/test_company_source_owned_execute.py')
names.extend(('tests/test_company_configuration.py', 'tests/test_company_configuration_native.py',
              'tests/test_company_release_producer.py'))
for name in names:
    if name in cli_helper_tests or name in ('test/test_checkpoint_admission.py','scripts/test-quota-admission.py','scripts/test-quota-command.py','scripts/test-runtime-layout.py','scripts/test-installation-identity.py','scripts/test-installation-wiring.py','scripts/test-installation-budgets.py','scripts/test-install-lock.py','scripts/test-startup-binding.py','scripts/test-runtime-pair-init.py','scripts/test-install-lock-verification.py','scripts/test-installer-parent.py','scripts/test-recovery-catalog.py','scripts/test-company-source.py','scripts/test-company-release.py','scripts/test-qualify-trivy-feed.py','tests/test_installer_materialize.py','tests/test_company_foundation.py','tests/test_platform_source.py','tests/test_company_release_schema4.py','tests/test_company_platform_issuance.py','tests/test_authenticated_seed.py','tests/test_company_platform_store.py','tests/test_platform_git_runner.py','tests/test_install_session_stage_binding.py','tests/test_company_stored_platform_source.py','tests/test_company_source_tree.py','tests/test_company_source_guard.py','tests/test_company_source_guard_backend.py','tests/test_company_captured_loader.py','tests/test_company_full_entry.py','tests/test_company_stored_startup.py','tests/test_company_fresh_assembly.py','tests/test_platform_foundation_materialize.py','tests/test_company_full_plan.py','tests/test_company_full_package.py','tests/test_company_full_package_loader.py','tests/test_company_runtime_pair_parent.py','tests/test_company_full_package_emit.py','tests/test_company_stage_scope.py','tests/test_company_full_retention_worker.py','tests/test_company_parent_system.py','tests/test_company_seed_backend.py','tests/test_company_seed_runner.py','tests/test_company_retention_effects.py','tests/test_company_full_cli_package.py','tests/test_company_full_cli.py','tests/test_company_release_crypto.py'):
        os.environ['AUTOSOFT_TEST_ARTIFACT_ROOT']=str(folder)
    if name=='tests/test_company_foundation.py':
        os.environ.pop('AUTOSOFT_FOUNDATION_TEST_PROPOSAL',None)
    if name in ('tests/test_company_release_producer.py','tests/test_company_runtime_identity.py'):
        os.environ['DOXENTRIQ_NATIVE_TEST_ROOT']=str(folder)
    path=source/name
    module_name='company_'+name.replace('-','_').replace('.','_')
    spec=importlib.util.spec_from_file_location(module_name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[module_name]=module;spec.loader.exec_module(module)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(module))
    skipped=[dict(test=test.id(),reason=reason) for test,reason in result.skipped]
    if not result.wasSuccessful() or result.testsRun==0 or any(name!='scripts/test-samba.py' or not item['test'].endswith('.test_real_sdk_readonly_constants_available_in_company_image') for item in skipped):
        raise SystemExit('A company policy check failed or required coverage was skipped: '+name)
    reports.append(dict(file=name,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),testsRun=result.testsRun,passed=result.testsRun-len(skipped),skipped=skipped))
(folder/'policy-results.json').write_text(json.dumps(reports,indent=2)+'\n')
PY
python3 - "$FIXTURE" "$DATA_DIR" <<'PY'
import pathlib,sys
folder=pathlib.Path(sys.argv[1])
names=['MYSQL','REDIS','RABBITMQ','REGISTRY','CADDY','NODE','PYTHON','KEYCLOAK','LEGO','PROMETHEUS','LOKI','GRAFANA','OTEL','TRIVY','PLATFORM','RUNTIME','DEPENDENCY_PROXY']
data=folder/'compose-data'
(data/'secrets').mkdir(parents=True)
(data/'secrets/dns.env').write_text('')
env=dict(DATA_DIR=str(data),DOCKER_GID='10001',ADMIN_ORIGIN='https://admin.test.internal',APPS_BASE_URL='https://apps.test.internal',AUTH_ORIGIN='https://identity.test.internal',OIDC_ISSUER='https://identity.test.internal/realms/platform',OWNER_SUBJECT='00000000-0000-4000-8000-000000000001',JOB_BUDGET_USD='1',MONTHLY_BUDGET_USD='10')
env.update({name+'_IMAGE':'example/never-run@sha256:'+'a'*64 for name in names})
(folder/'compose.env').write_text('\n'.join(k+'='+v for k,v in env.items())+'\n')
PY
docker compose --env-file "$FIXTURE/compose.env" -f "$SOURCE_ROOT/deploy/compose.yaml" config --quiet
python3 - "$GO_IMAGE" "$FIXTURE" "$SOURCE_ROOT" "$SOURCE_MANIFEST" "${BASH_SOURCE[0]}" <<'PY'
from datetime import datetime,timezone
import hashlib,json,pathlib,sys
folder=pathlib.Path(sys.argv[2])
policies=json.loads((folder/'policy-results.json').read_text())
go_events=[json.loads(line) for line in (folder/'go-tests.jsonl').read_text().splitlines()]
go_passes=[event for event in go_events if event.get('Action')=='pass' and event.get('Test')]
report=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='passed',scope='company Go tests and infrastructure syntax/policy checks on Rocky Linux 10.2',goImage=sys.argv[1],checks=['Go 1.27.3 exact toolchain','Checksum-locked company module download','Actual Go tests UID10001/runsc/read-only source/no network/no host socket or credentials','Go vet offline with the same sandbox restrictions','Linux shell and Python syntax','Actual bootstrap PKI chain, preserved-key rerun and legacy/wrong-identity rejection','Deployment image/resource/signature/mirror policy','Recovery chain continuity/documents and isolated replay-tool policy','Cold Redis/Rabbit clone isolation and immutable backup-writer quiescence policy; native recovery evidence is separate','Identity recovery configuration policy; live PKCE/recovery proof is separate','Samba path/scope/token/read-only/relay policy; live SDK qualification is separate','Filesystem scope/HTTP policy and actual Linux openat2 kernel containment tests; real runsc read-only mount qualification is separate','Actual Docker Compose config parse against synthetic never-run image references'],policyChecks=policies,goTests=dict(topLevelPassed=sum('/' not in event['Test'] for event in go_passes),subtestsPassed=sum('/' in event['Test'] for event in go_passes),packagesPassed=sum(event.get('Action')=='pass' and not event.get('Test') for event in go_events),eventLogSha256=hashlib.sha256((folder/'go-tests.jsonl').read_bytes()).hexdigest()),limitations=['Full platform/company image build, app publishing, provider qualification and remaining OS matrix are not accepted by this test','Samba policy host checks do not establish live SMB coverage; any SDK skip is recorded explicitly, and the separate immutable connector-image rehearsal provides actual SDK/protocol evidence'],modelApiCalls=0)
proof=pathlib.Path(sys.argv[4]); manifest=json.loads(proof.read_text())
report['sourceSnapshot']=dict(sourceDirectory=sys.argv[3],sourceManifestPath=str(proof),sourceManifestSha256=hashlib.sha256(proof.read_bytes()).hexdigest(),archiveSha256=manifest['archiveSha256'],fileManifestSha256=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),fileCount=len(manifest['files']))
report['testRunner']=dict(path=sys.argv[5],sha256=hashlib.sha256(pathlib.Path(sys.argv[5]).read_bytes()).hexdigest())
report['checks'].append('Trusted filelog redaction, root/Linux reader permissions, immutable source identity and persistent offset configuration policy; actual TLS ingestion/restart proof is separate')
report['checks'].append('Running-kernel vendor/source identity, signed Debian Built-Using, active/newer Rocky kernel, bounded read-only queries, feed freshness and race policy; actual host advisory evidence is separate')
report['checks'].append('Fresh fixed-path OS metadata inventory, root ownership, link/size/membership/race boundaries and nonempty RPM transaction-journal denial; actual host scan coverage is separate')
report['checks'].append('Bounded maintenance scanner lifecycle, exact captured-ID cleanup, uncertain-input retention, local Docker endpoint and empty CLI configuration policy; actual scanner/cache/protocol proof is separate')
report['checks'].append('Fixed typed scanner failure details in actual maintenance caller gate/daily reports; arbitrary error summaries and raw secrets remain excluded')
report['checks'].append('Quota pending-state non-replay, exact readback parsers, bounded subprocesses and isolated helper loading; native XFS enforcement and service qualification remain separate')
report['checks'].append('Host remediation inventory, authenticated candidate bindings, complete simulated changes and running-kernel preservation; live vendor queries, native solvers, tested fixes and apply remain separate')
report['checks'].append('Copied host inventory decoding, fixed private bounded query capture and complete before/after metadata/tool preservation; native package manager/configuration and vendor authentication remain separate')
report['checks'].append('Fixed scanner failure stages and observed exit codes, diagnostic-storage fault cleanup, strict progress retention and portable original-security AST bindings; native diagnostic behavior remains separate')
report['checks'].append('Bounded immutable image export, independently hashed stored OCI layers, private failure evidence and confirmed-only seven-day diagnostic retention policy; actual Linux export/scanner proof is separate')
report['checks'].append('Durable backup original-ID intents, uncertain-outcome non-replay and retained original-only reconciliation controls; real Docker interruptions, writer coordination and power-loss durability remain separate')
report['checks'].append('Checkpoint admission PRIMITIVE_ONLY: durable CLOSED fences, exact activity/lock/directory identity, unresolved-intent retention and concurrent lease policy; native durability and complete backup coordination remain separate')
report['checks'].append('Quota admission HOST_QUOTA_ONLY: durable project/hash binding, allocation mutex scope, pending/native/final completion ordering and unresolved-outcome policy; native XFS/flock, fresh installer initialization and complete backup coordination remain separate')
report['checks'].append('Trusted quota command ownership, finite private runtime layout and persisted installation identity controls; native process, mount, installer and supported OS qualification remain separate')
report['checks'].append('Fresh identity/storage receipt wiring, finite positive spending inputs before credential writes and standalone inode-bound installer lock controls; native installation, lock wiring and interrupted-stage reconciliation remain separate')
report['checks'].append('Read-only initialized startup binding, fresh-only runtime pair initialization and company verifier descriptor/environment controls; injected local evidence does not qualify native mount/lock/parent authority, installer wiring, reconciliation or platform readiness')
report['checks'].append('Held original installer-parent evidence and combined recovery catalog cursor/index commit-before-resume controls, with finite protected metadata and unresolved-state denial; injected policy evidence does not qualify native parent/flock/durability, scalable retention or complete backup coordination')
report['checks'].append('Explicit company source byte catalog, canonical manifests, protected held file descriptors and literal script/sibling coverage controls; bootstrap signature trust, host activation input coverage and native source loading remain separate')
report['checks'].append('Schema2 captured release/source authentication and isolated offline scanner controller controls; injected seams and synthetic signatures do not qualify Linux memfd, installer activation, actual scanner semantics or production eligibility')
report['checks'].append('Complete held company source, explicit read-only backend, captured startup composition and additive full-entry controls; source/injected runs do not qualify native ABI, capacity, full caller activation or trusted company release provenance')
report['checks'].append('Held confirmed stored-startup journals and exact original parent action/outcome bindings before captured composition; separate injected 23-control evidence does not qualify native startup, full installation, outer closure or production readiness')
(folder.parent/'company-linux-report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
PY

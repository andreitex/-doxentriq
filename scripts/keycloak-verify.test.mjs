import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyInitialIdentity, runNativeIdentity, IdentityProvisioningError } from './keycloak-provision.mjs';
const id = n => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');
const config = { action: 'verify-initial', ownerSubject: id(1), adminOrigin: 'https://admin.example.invalid', ssoAliases: [],
  bootstrapPassword: 'synthetic-bootstrap-credential', provisionerSecret: 'synthetic-provisioner-credential', directoryReaderSecret: 'synthetic-reader-credential-value' };
const realm = { realm: 'platform', enabled: true, sslRequired: 'all', registrationAllowed: false, resetPasswordAllowed: false,
  loginWithEmailAllowed: true, duplicateEmailsAllowed: false, bruteForceProtected: true, failureFactor: 5,
  accessTokenLifespan: 300, ssoSessionIdleTimeout: 1800, ssoSessionMaxLifespan: 28800,
  passwordPolicy: 'length(16) and digits(1) and lowerCase(1) and upperCase(1) and specialChars(1)',
  otpPolicyType: 'totp', otpPolicyAlgorithm: 'HmacSHA1', otpPolicyDigits: 6, otpPolicyPeriod: 30, otpPolicyLookAheadWindow: 1, browserFlow: 'platform-browser' };

test('actual packaged worker payload is accepted by the real helper with controlled identity transport',async()=>{
 const program=String.raw`
import base64,importlib.util,json,os,sys,types
from pathlib import Path
root=Path(sys.argv[1]);base=Path(os.environ.get('DOXENTRIQ_BASE_SOURCE',root))
def read(path,limit):
 relative=path.relative_to(root);candidate=root/relative
 return (candidate if candidate.exists() else base/relative).read_bytes()
path=base/'deploy/installer/build-native-retention-package.py'
spec=importlib.util.spec_from_file_location('identity_contract_builder',path);B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
raw=B.assemble(root,'a'*64,reader=read)
worker=types.ModuleType('identity_contract_package');exec(compile(raw,'<synthetic trust worker>','exec'),worker.__dict__)
def captured(name):
 row=worker.PACKAGE['programs'][name];raw=base64.b64decode(row['base64'],validate=True)
 assert len(raw)==row['bytes'] and __import__('hashlib').sha256(raw).hexdigest()==row['sha256']
 value=types.ModuleType('identity_contract_'+name);exec(compile(raw,'<captured '+name+'>','exec'),value.__dict__)
 return value
W=captured('identity_worker');Q=captured('configuration')
assert W.PROVISION=='scripts/keycloak-provision.mjs'
values={name:b'a'*43 for name in ('secrets/keycloak/bootstrap-password','secrets/runtime/keycloak-client','secrets/runtime/keycloak-directory-reader')}
_,payload=W.payloads(Q,types.SimpleNamespace(read=lambda p:values[p]),json.loads(sys.argv[2]))
sys.stdout.buffer.write(payload)
`;
 const root=fileURLToPath(new URL('../',import.meta.url));
 const result=spawnSync(process.env.DOXENTRIQ_TEST_PYTHON||'python3',['-I','-B','-c',program,root,JSON.stringify({
   owner_subject:config.ownerSubject,admin_origin:config.adminOrigin,sso:'none'})],{encoding:'utf8',timeout:20000,maxBuffer:1024*1024});
 assert.ifError(result.error);assert.equal(result.status,0,result.stderr);
 const actual=JSON.parse(result.stdout);assert.equal(actual.adminOrigin,config.adminOrigin);assert.deepEqual(actual.ssoAliases,[]);
 const f=fixture();await runNativeIdentity(actual,f.options);
 assert.deepEqual(JSON.parse(f.output[0]),{scope:'INITIAL_IDENTITY_POLICY_READBACK',ownerSubject:config.ownerSubject,
   configuredPolicyVerified:true,browserMfaQualified:false,publicStartupAllowed:false});
 assert.equal(f.requests[0].url,'https://keycloak:9000/health/ready');
 assert.ok(f.requests.filter(r=>r.options.method==='POST').every(r=>r.url.endsWith('/token')));
});

function fixture(edit = (path, value) => value) {
  const requests = [], output = [], rows = new Map();
  const put = (path, value) => rows.set('/admin/realms/' + path, value);
  const owner = { id: id(1), username: 'owner', enabled: true, requiredActions: ['UPDATE_PASSWORD', 'CONFIGURE_TOTP', 'CONFIGURE_RECOVERY_AUTHN_CODES'] };
  const reader = { id: id(2), username: 'service-account-platform-directory-reader', enabled: true };
  const local = { id: id(3), username: 'service-account-platform-provisioner', enabled: true };
  put('platform', realm);put('platform/roles/platform-owner/users?first=0&max=2', [owner]);put('platform/roles/platform-admin/users?first=0&max=2', [owner]);
  put('platform/users/'+id(1), owner);put('platform/users/'+id(1)+'/credentials', [{type:'password'}]);put('platform/users/'+id(1)+'/federated-identity', []);
  for (const user of [owner, reader, local]) {
    put('platform/users/'+user.id+'/role-mappings/realm/composite', user===owner ? [{name:'platform-owner'},{name:'platform-admin'}] : [{name:'default-roles-platform'}]);
    put('platform/users/'+user.id+'/groups?first=0&max=1', []);
  }
  put('platform/groups?first=0&max=1', []);
  put('platform/users?enabled=true&first=0&max=4', [owner, reader, local]);put('platform/users?enabled=false&first=0&max=1', []);
  put('platform/authentication/required-actions', owner.requiredActions.map(alias=>({alias,providerId:alias,enabled:true})));
  const exec = (providerId, requirement, index, cfg) => ({providerId,requirement,index,level:0,...(cfg?{authenticationConfig:id(cfg)}:{})});
  const flow = (name, requirement, index) => ({displayName:name,authenticationFlow:true,requirement,index,level:0});
  put('platform/authentication/flows/platform-browser/executions', [exec('identity-provider-redirector','ALTERNATIVE',0),flow('platform-forms','ALTERNATIVE',1)]);
  put('platform/authentication/flows/platform-forms/executions', [exec('auth-username-password-form','REQUIRED',0,40),flow('platform-owner-second-factor','CONDITIONAL',1)]);
  put('platform/authentication/flows/platform-owner-second-factor/executions', [exec('conditional-user-configured','REQUIRED',0),exec('auth-otp-form','ALTERNATIVE',1,41),exec('auth-recovery-authn-code-form','ALTERNATIVE',2,42)]);
  put('platform/authentication/flows/platform-sso-otp/executions', [exec('auth-otp-form','REQUIRED',0,41)]);
  for (const [number,alias,value] of [[40,'verified-password','pwd'],[41,'verified-otp','otp'],[42,'verified-owner-recovery','mfa']])
    put('platform/authentication/config/'+id(number),{alias,config:{'default.reference.value':value,'default.reference.maxAge':'1800'}});
  put('platform/identity-provider/instances', []);
  function client(realmName,name,number,extra={}) {
    const value={id:id(number),clientId:name,enabled:true,protocol:'openid-connect',publicClient:false,standardFlowEnabled:false,
      directAccessGrantsEnabled:false,implicitFlowEnabled:false,serviceAccountsEnabled:true,fullScopeAllowed:false,...extra};
    put(realmName+'/clients?clientId='+name,[{id:value.id}]);put(realmName+'/clients/'+value.id,value);return value;
  }
  client('platform','autosoft-admin',10,{standardFlowEnabled:true,serviceAccountsEnabled:false,redirectUris:[config.adminOrigin+'/auth/callback'],webOrigins:[config.adminOrigin],attributes:{'pkce.code.challenge.method':'S256'},protocolMappers:[
    {name:'verified-authentication-method',protocol:'openid-connect',protocolMapper:'oidc-amr-mapper',config:{'id.token.claim':'true','access.token.claim':'true'}},
    {name:'admin-audience',protocol:'openid-connect',protocolMapper:'oidc-audience-mapper',config:{'included.client.audience':'autosoft-admin','access.token.claim':'true','id.token.claim':'false'}},
    {name:'verified-identity-provider',protocol:'openid-connect',protocolMapper:'oidc-usersessionmodel-note-mapper',config:{'user.session.note':'identity_provider','claim.name':'identity_provider','jsonType.label':'String','access.token.claim':'true','id.token.claim':'true'}}]});
  client('master','autosoft-provisioner',11,{fullScopeAllowed:true});put('master/clients/'+id(11)+'/service-account-user',{id:id(4)});
  put('master/users/'+id(4)+'/role-mappings/realm/composite',[{name:'create-realm'}]);put('master/users/'+id(4)+'/role-mappings',{});
  client('platform','platform-directory-reader',12,{attributes:{'autosoft.directory-reader':'1'}});put('platform/clients/'+id(12)+'/service-account-user',reader);
  client('platform','platform-provisioner',13);put('platform/clients/'+id(13)+'/service-account-user',local);
  client('platform','realm-management',14);
  const roles=['view-users','view-realm','view-identity-providers'].map(name=>({name,clientRole:true,containerId:id(14)}));
  put('platform/users/'+id(2)+'/role-mappings/clients/'+id(14),roles);
  put('platform/clients/'+id(12)+'/scope-mappings/clients/'+id(14),roles);
  put('platform/users/'+id(2)+'/role-mappings',{clientMappings:{management:{id:id(14),mappings:roles}}});
  put('master/clients?first=0&max=33',[{id:id(11),clientId:'autosoft-provisioner'},{id:id(15),clientId:'master-realm'},{id:id(16),clientId:'platform-realm'}]);
  put('platform/clients?first=0&max=33',[{id:id(10),clientId:'autosoft-admin'},{id:id(12),clientId:'platform-directory-reader'},{id:id(13),clientId:'platform-provisioner'},{id:id(14),clientId:'realm-management'}]);
  for (const clientId of [11,15,16]) put('master/users/'+id(4)+'/role-mappings/clients/'+id(clientId)+'/composite',[]);
  for (const userId of [2,3]) for (const clientId of [10,12,13,14]) {
    const names=clientId!==14?[]:userId===2?['query-groups','query-users','view-users','view-realm','view-identity-providers']:['manage-clients'];
    put('platform/users/'+id(userId)+'/role-mappings/clients/'+id(clientId)+'/composite',names.map(name=>({name,clientRole:true,containerId:id(clientId)})));
  }
  const fetchImpl=async(url,options)=>{
    requests.push({url,options});assert.equal(options.redirect,'error');assert.ok(options.signal instanceof AbortSignal);
    const u=new URL(url),path=u.pathname+u.search;
    if (u.port==='9000') {assert.equal(url,'https://keycloak:9000/health/ready');return new Response(JSON.stringify(edit(path,{status:'UP',checks:[{name:'database',status:'UP'}]})),{status:200});}
    assert.equal(u.origin,'https://keycloak:8443');
    if (path.endsWith('/token')) return new Response(JSON.stringify({access_token:'synthetic-access-token'}),{status:200});
    assert.equal(options.method??'GET','GET','Verifier may not mutate identity state');
    assert.ok(rows.has(path),'Unexpected API path '+path);
    return new Response(JSON.stringify(edit(path,structuredClone(rows.get(path)))),{status:200});
  };
  return {requests,output,options:{fetchImpl,output:value=>output.push(value)}};
}

test('independent initial policy readback uses only GETs and token acquisition and never grants public startup',async()=>{
 const f=fixture();await runNativeIdentity(config,f.options);
 const value=JSON.parse(f.output[0]);assert.equal(value.configuredPolicyVerified,true);assert.equal(value.browserMfaQualified,false);assert.equal(value.publicStartupAllowed,false);
 assert.equal(f.requests[0].url,'https://keycloak:9000/health/ready');
 assert.ok(f.requests.filter(r=>r.options.method==='POST').every(r=>r.url.endsWith('/token')));
 assert.ok(!JSON.stringify(f.output).includes('synthetic-'));
});

for (const [name,change] of [
 ['masked authentication reference', (p,v)=>p.endsWith('/authentication/config/'+id(42))?{...v,config:{...v.config,'default.reference.value':'**********'}}:v],
 ['wrong authentication reference', (p,v)=>p.endsWith('/authentication/config/'+id(40))?{...v,config:{...v.config,'default.reference.value':'mfa'}}:v],
 ['inherited group grant', (p,v)=>p==='/admin/realms/platform/groups?first=0&max=1'?[{id:id(50),name:'unexpected-admin-group'}]:v],
 ['composite service-account admin grant', (p,v)=>p.endsWith('/users/'+id(3)+'/role-mappings/realm/composite')?[...v,{name:'platform-admin'}]:v],
 ['second local owner', (p,v)=>p.includes('/roles/platform-owner/users?')?[...v,{id:id(55),username:'other'}]:v],
 ['unsafe admin redirect', (p,v)=>p==='/admin/realms/platform/clients/'+id(10)?{...v,redirectUris:['https://unexpected.example.invalid/*']}:v],
 ['password-only browser flow', (p,v)=>p.includes('/platform-owner-second-factor/executions')?v.filter(r=>r.providerId!=='auth-otp-form'):v],
 ['disabled hidden identity', (p,v)=>p==='/admin/realms/platform/users?enabled=false&first=0&max=1'?[{id:id(59),username:'hidden',enabled:false}]:v],
 ['reader inherited client write grant', (p,v)=>p.endsWith('/users/'+id(2)+'/role-mappings/clients/'+id(14)+'/composite')?[...v,{name:'manage-users',clientRole:true,containerId:id(14)}]:v],
 ['local provisioner inherited client write grant', (p,v)=>p.endsWith('/users/'+id(3)+'/role-mappings/clients/'+id(14)+'/composite')?[...v,{name:'manage-users',clientRole:true,containerId:id(14)}]:v],
 ['master inherited administrative client grant', (p,v)=>p.endsWith('/users/'+id(4)+'/role-mappings/clients/'+id(16)+'/composite')?[{name:'realm-admin',clientRole:true,containerId:id(16)}]:v],
]) test(name+' refuses without mutation or success output',async()=>{
 const f=fixture(change);await assert.rejects(verifyInitialIdentity(config,f.options),IdentityProvisioningError);assert.deepEqual(f.output,[]);
 assert.ok(f.requests.filter(r=>r.options.method==='POST').every(r=>r.url.endsWith('/token')));
});

test('management readiness failure makes no token or provisioning request and is not retried',async()=>{
 const f=fixture((p,v)=>p==='/health/ready'?{status:'DOWN',checks:[]}:v);
 await assert.rejects(runNativeIdentity({...config,action:undefined},f.options),IdentityProvisioningError);
 assert.equal(f.requests.length,1);assert.deepEqual(f.output,[]);
});

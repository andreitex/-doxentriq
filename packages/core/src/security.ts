import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, writeFile, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import type { ApprovalRecord, Principal, ReleaseRecord, Evidence } from './types.js';
import { stages, imageSchema } from './schemas.js';

function canonical(value:unknown):unknown {
  if(Array.isArray(value)) return value.map(canonical);
  if(value && typeof value==='object') return Object.fromEntries(Object.entries(value).filter(([,v])=>v!==undefined).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,v])=>[k,canonical(v)]));
  if(typeof value==='number' && !Number.isFinite(value)) throw new Error('Non-finite artifact value');
  return value;
}
export function hashArtifact(value:unknown):string{return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');}
export function releaseArtifactHash(r:ReleaseRecord):string {
  return hashArtifact({appId:r.appId,commit:r.commit,images:r.images,schemaVersion:r.schemaVersion,compatibleSchemaMin:r.compatibleSchemaMin,compatibleSchemaMax:r.compatibleSchemaMax,migrations:r.migrations,baseReleaseId:r.baseReleaseId,summary:r.summary,evidence:r.evidence,...(r.migrationSnapshot ? {migrationSnapshot:r.migrationSnapshot}: {})});
}
export function safeEqual(a:string,b:string):boolean { const x=Buffer.from(a),y=Buffer.from(b); return x.length===y.length && timingSafeEqual(x,y); }
export function redact<T>(value:T,knownSecrets:string[]=[]):T {
  const secretNames=/^(password|passwd|credentials|token|access[_-]?token|refresh[_-]?token|id[_-]?token|authorization|api[_-]?key|client[_-]?secret|secret|secret[_-]?key|private[_-]?key|signing[_-]?secrets?|cookie|set[_-]?cookie)$/i;
  // Only recognized assignments are interpreted. Keep complete credential values
  // out of embedded diagnostics, including JSON serialized inside another string.
  const names=secretNames.source.slice(1,-1);
  const credentialMarker=new RegExp(String.raw`\b${names}(?:\\*["'])?\s*[:=]`,'i');
  const bareAssignment=new RegExp(String.raw`${names}\s*[:=]\s*`,'iy');
  const followingAssignment=/[ \t]+[A-Za-z][A-Za-z0-9_-]*[ \t]*[:=]/y;
  const authorizationValue=/(?:Basic|Bearer)[ \t]+[^\s,;}\]]+/iy;
  const scanLimit={};
  // These are JavaScript runtime expressions / Fetch policy enums, not stored
  // credentials. Preserve their syntax inside source nested in model JSON.
  // Literal tokens, computed template expressions and arbitrary values still
  // take the ordinary credential-redaction path below.
  const runtimeMemberEnd=(text:string,start:number,name:string,colon:boolean):number|undefined=>{
    if(!colon)return;
    const value=text.slice(start,start+512);
    const match=/^authorization$/i.test(name)
      ? /^`Bearer \$\{[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\}`(?=[\s,}]|$)/.exec(value)
      : /^credentials$/i.test(name)?/^(['"])(?:omit|same-origin|include)\1(?=[\s,}]|$)/.exec(value):null;
    const end=match?start+match[0].length:undefined;
    return end!==undefined&&(end===text.length||/[\s,}]/.test(text[end]!))?end:undefined;
  };
  function assignments(original:string):string {
    let remaining=2*1024*1024;
    const spend=(count=1)=>{if(count>remaining)throw scanLimit;remaining-=count;};
    const quotedEnd=(text:string,start:number):number=>{
      const quote=text[start];
      for(let i=start+1;i<text.length&&i-start<=65536;i++){
        spend();
        if(text[i]==='\\'){spend();i++;}
        else if(text[i]===quote)return i+1;
      }
      throw scanLimit;
    };
    const templateEnd=(text:string,start:number,depth=0):number=>{
      if(depth>=32)throw scanLimit;
      let braces=0;
      for(let i=start+1;i<text.length&&i-start<=65536;i++){
        spend();const c=text[i]!;
        if(c==='\\'){spend();i++;continue;}
        if(!braces){
          if(c==='`')return i+1;
          if(c==='$'&&text[i+1]==='{'){braces=1;spend();i++;}
        }else{
          if(c==='"'||c==="'"){i=quotedEnd(text,i)-1;continue;}
          if(c==='`'){i=templateEnd(text,i,depth+1)-1;continue;}
          if(c==='{'){if(++braces>32)throw scanLimit;}
          else if(c==='}')braces--;
        }
      }
      throw scanLimit;
    };
    const valueEnd=(text:string,start:number,cookieHeader=false):number=>{
      // Bare HTTP cookie headers contain multiple semicolon-separated values.
      // JSON quoted-key values continue to use their complete member boundary.
      if(cookieHeader){
        let end=start;for(;end<text.length&&!/[\r\n]/.test(text[end]!);end++){spend();if(end-start>65536)throw scanLimit;}
        return end;
      }
      if(text[start]==='"'||text[start]==="'")return quotedEnd(text,start);
      if(text[start]==='`')return templateEnd(text,start);
      if(text[start]==='['||text[start]==='{'){
        const stack:string[]=[];
        for(let i=start;i<text.length&&i-start<=65536;i++){
          spend();const c=text[i]!;
          if(c==='"'||c==="'"){i=quotedEnd(text,i)-1;continue;}
          if(c==='`'){i=templateEnd(text,i)-1;continue;}
          if(c==='['||c==='{'){if(stack.length>=32)throw scanLimit;stack.push(c);}
          else if(c===']'||c==='}'){
            if(stack.pop()!==(c===']'?'[':'{'))throw scanLimit;
            if(!stack.length)return i+1;
          }
        }
        throw scanLimit;
      }
      authorizationValue.lastIndex=start;const authorization=authorizationValue.exec(text);
      if(authorization){spend(authorization[0].length);if(authorization[0].length>65536)throw scanLimit;return start+authorization[0].length;}
      let i=start;
      for(;i<text.length;i++){
        spend();if(i-start>65536)throw scanLimit;
        if(/[\r\n,;}\]]/.test(text[i]!))break;
        if(text[i]===' '||text[i]==='\t'){
          followingAssignment.lastIndex=i;if(followingAssignment.test(text))break;
          while(text[i+1]===' '||text[i+1]==='\t'){spend();i++;if(i-start>65536)throw scanLimit;}
        }
      }
      return i;
    };
    const scan=(text:string,depth:number):string=>{
      const parts:string[]=[];let emitted=0;
      for(let i=0;i<text.length;){
        spend();const c=text[i]!;
        if(c==='"'||c==="'"&&(i===0||!/[A-Za-z0-9]/.test(text[i-1]!))){
          const end=quotedEnd(text,i),raw=text.slice(i,end);let decoded:string;
          if(c==='"'){
            try{decoded=JSON.parse(raw) as string;}catch{decoded=raw.slice(1,-1);}
          }else decoded=raw.slice(1,-1).replace(/\\(['\\])/g,'$1');
          let after=end;while(/\s/.test(text[after]??'')&&after<text.length){spend();after++;}
          if(secretNames.test(decoded)&&(text[after]===':'||text[after]==='=')){
            let start=after+1;while(/\s/.test(text[start]??'')&&start<text.length){spend();start++;}
            const runtime=runtimeMemberEnd(text,start,decoded,text[after]===':'&&text[start]==='`');
            if(runtime!==undefined){spend(runtime-start);i=runtime;continue;}
            const last=valueEnd(text,start);
            parts.push(text.slice(emitted,start),'"[REDACTED]"');emitted=last;i=last;continue;
          }
          if(credentialMarker.test(decoded)||/\\u[0-9a-f]{4}/i.test(decoded)){
            const cleaned=depth>=8?'[REDACTED]':scan(decoded,depth+1);
            if(cleaned!==decoded){
              const encoded=c==='"'?JSON.stringify(cleaned):"'"+cleaned.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\r/g,'\\r').replace(/\n/g,'\\n')+"'";
              parts.push(text.slice(emitted,i),encoded);emitted=end;
            }
          }
          i=end;continue;
        }
        if(/[A-Za-z]/.test(c)&&(i===0||!/[A-Za-z0-9_-]/.test(text[i-1]!))){
          bareAssignment.lastIndex=i;const head=bareAssignment.exec(text);
          if(head){
            spend(head[0].length);const start=i+head[0].length;
            const runtime=runtimeMemberEnd(text,start,head[1]??'',head[0].includes(':'));
            if(runtime!==undefined){spend(runtime-start);i=runtime;continue;}
            const last=valueEnd(text,start,/^(?:cookie|set[_-]?cookie)$/i.test(head[1]??''));
            parts.push(text.slice(emitted,start),'"[REDACTED]"');emitted=last;i=last;continue;
          }
        }
        i++;
      }
      return parts.length?parts.join('')+text.slice(emitted):text;
    };
    try{return scan(original,0);}catch(error){
      if(error!==scanLimit)throw error;
      // Uninspected text may hide a later escaped credential name. Once a
      // bounded inspection fails, no remaining text can be established benign.
      return '[REDACTED]';
    }
  }
  const clean=(v:unknown):unknown=>{
    if(typeof v==='string') {
      let s=assignments(v).replace(/-----BEGIN ((?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/g,'[REDACTED]').replace(/\b(sk-[a-zA-Z0-9_-]{16,}|AIza[a-zA-Z0-9_-]{20,})\b/g,'[REDACTED]').replace(/\b(?:whsec_[A-Za-z0-9_+/=-]{16,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9_]{16,})(?![A-Za-z0-9_+/=-])/g,'[REDACTED]').replace(/Bearer\s+[a-zA-Z0-9._~+/-]+/gi,'Bearer [REDACTED]').replace(/([a-z]+:\/\/[^:\s/]+:)[^@\s]+@/gi,'$1[REDACTED]@');
      for(const secret of knownSecrets.filter(s=>s.length>=4)) s=s.split(secret).join('[REDACTED]');
      return s;
    }
    if(Array.isArray(v))return v.map(clean);
    if(v&&typeof v==='object')return Object.fromEntries(Object.entries(v).map(([k,val])=>[k,secretNames.test(k)?'[REDACTED]':clean(val)]));
    return v;
  };return clean(value) as T;
}
export class SecretVault {
  constructor(private readonly key:Buffer,private readonly directory:string){if(key.length!==32)throw new Error('Vault key must contain exactly 32 bytes');}
  async put(value:string,context:string):Promise<string>{
    if(!context||value.length>65536)throw new Error('Invalid secret context or size');
    await mkdir(this.directory,{recursive:true,mode:0o700});
    const ref=randomBytes(24).toString('hex'),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key,iv);cipher.setAAD(Buffer.from(context));
    const content=Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
    await writeFile(path.join(this.directory,ref+'.json'),JSON.stringify({v:1,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:content.toString('base64')}),{mode:0o600,flag:'wx'});return ref;
  }
  async get(ref:string,context:string):Promise<string>{
    if(!/^[a-f0-9]{48}$/.test(ref))throw new Error('Invalid secret reference');
    const filename=path.join(this.directory,ref+'.json');if((await lstat(filename)).isSymbolicLink())throw new Error('Secret references cannot be symlinks');
    const envelope=JSON.parse(await readFile(filename,'utf8')) as {v:number;iv:string;tag:string;data:string};if(envelope.v!==1)throw new Error('Unsupported secret envelope');
    const decipher=createDecipheriv('aes-256-gcm',this.key,Buffer.from(envelope.iv,'base64'));decipher.setAAD(Buffer.from(context));decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
    return Buffer.concat([decipher.update(Buffer.from(envelope.data,'base64')),decipher.final()]).toString('utf8');
  }
}
export async function resolveWithin(root:string,relative:string):Promise<string>{
  // Validate portable project paths before consulting this host's path rules:
  // POSIX treats Windows drive/alternate-stream syntax as ordinary filenames.
  if(!relative||relative.includes('\\')||relative.includes(':')||/[\x00-\x1f\x7f]/.test(relative)||path.isAbsolute(relative)||relative.split('/').some(s=>s==='..'||s==='.'||s===''))throw new Error('Unsafe project path');
  const resolvedRoot=await realpath(root),candidate=path.resolve(root,relative);
  if(!candidate.startsWith(resolvedRoot+path.sep))throw new Error('Path escapes project root');
  let parent=path.dirname(candidate);
  while(parent!==resolvedRoot){try{const actual=await realpath(parent);if(actual!==parent || !actual.startsWith(resolvedRoot+path.sep))throw new Error('Symlink in project path');break;}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;parent=path.dirname(parent);}}
  try{if((await lstat(candidate)).isSymbolicLink())throw new Error('Symlink output forbidden');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  return candidate;
}
export type ReleaseGateContext={currentReleaseId:string|null;currentSchemaVersion:number;action:'publish'|'rollback'|'emergency_rollback';principal:Principal;approval?:ApprovalRecord;now?:Date;checkpointVerified?:boolean;securityEvidence?:Evidence};
export function evaluateReleaseGate(release:ReleaseRecord,context:ReleaseGateContext):{allowed:boolean;reasons:string[]}{
  const reasons:string[]=[],now=context.now??new Date(),p=context.principal,a=context.approval;
  if(!p.mfa)reasons.push('MFA is required');
  if(!p.roles.some(r=>['platform-owner','platform-admin','publisher'].includes(r)))reasons.push('Publication permission is required');
  if(context.action==='emergency_rollback'&&!p.localOwner)reasons.push('Only the permanent local owner can approve an emergency rollback');
  if(context.action==='publish'&&release.baseReleaseId!==context.currentReleaseId)reasons.push('The application changed after this release was prepared');
  if(context.currentSchemaVersion<release.compatibleSchemaMin||context.currentSchemaVersion>release.compatibleSchemaMax)reasons.push('This release is incompatible with the current database schema');
  if(!/^[a-f0-9]{40,64}$/.test(release.commit))reasons.push('A verified Git commit is required');
  if(!release.images.length||release.images.some(i=>!imageSchema.safeParse(i).success))reasons.push('All images must be pinned by digest');
  const e=release.evidence;
  if(e.status!=='passed')reasons.push('Verification is failed or unavailable');
  const evidenceNames=e.checks.map(c=>c.name);
  if(new Set(evidenceNames).size!==evidenceNames.length||e.checks.some(c=>!c.name||!c.passed))reasons.push('Verification contains duplicate, contradictory or failed checks');
  for(const stage of stages)if(e.checks.filter(c=>c.name===stage&&c.passed).length!==1)reasons.push(`Missing unique successful ${stage} gate`);
  const security=context.securityEvidence??e;
  if(!security.checks.length||new Set(security.checks.map(c=>c.name)).size!==security.checks.length||security.checks.some(c=>!c.name||!c.passed))reasons.push('Current security coverage contains missing, duplicate or failed checks');
  const inspectedVulnerableEmergency=context.action==='emergency_rollback'&&security.status==='failed'&&security.checks.length>0&&security.checks.every(c=>c.passed)&&security.findings.some(f=>['MEDIUM','HIGH','CRITICAL'].includes(f.severity));
  if(security.status!=='passed'&&!inspectedVulnerableEmergency)reasons.push('Current security scanning is failed or unavailable');
  for(const [label,date]of [['scan',security.checkedAt],['vulnerability feed',security.feedUpdatedAt]] as const){const time=Date.parse(date);if(!Number.isFinite(time)||time>now.getTime()+60000||now.getTime()-time>86400000)reasons.push(`The ${label} is missing or stale`);}
  if(security.findings.some(f=>['MEDIUM','HIGH','CRITICAL','UNKNOWN'].includes(f.severity))&&context.action!=='emergency_rollback')reasons.push('Known Medium-or-higher or unclassified findings block this release');
  if(security.findings.some(f=>f.severity==='UNKNOWN'))reasons.push('Unclassified findings require review before any publication or emergency rollback');
  if(release.migrations.some(m=>m.destructive)&&(!context.checkpointVerified||!a?.checkpointId))reasons.push('A verified recovery checkpoint is required before destructive changes');
  const expectedHash=releaseArtifactHash(release);
  if(release.artifactHash!==expectedHash)reasons.push('Release artifact verification failed');
  if(!a)reasons.push('Explicit release approval is required');
  else{
    if(a.releaseId!==release.id||a.appId!==release.appId||a.action!==context.action||a.artifactHash!==expectedHash)reasons.push('Approval does not match this exact action and artifact');
    if(!a.approvedBy||!a.approvedAt||a.consumedAt)reasons.push('Approval has not been granted or was already used');
    if(!Number.isFinite(Date.parse(a.expiresAt))||Date.parse(a.expiresAt)<=now.getTime())reasons.push('Approval expired');
  }
  return {allowed:reasons.length===0,reasons};
}

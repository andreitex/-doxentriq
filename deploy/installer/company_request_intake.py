"""Company-packaged, credential-free request intake; never installs or repairs.

The initial executing helper/entry must already be independently authenticated.
The externally supplied receipt digest binds the whole delivered package; a
matching self-generated receipt is not initial verifier trust. Original children
still authenticate release signatures/source and own installation admission.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from types import ModuleType
import uuid

PACKAGED = None  # @REQUEST_INTAKE_INPUTS@
BASE = PurePosixPath('/opt/autosoft-company')
PACKAGE = BASE/'bootstrap'
REQUESTS = BASE/'requests'
INTAKE = REQUESTS/'intake'
MAX_PACKAGE = 4*1024**2
FILES = {
    'company-install.sh': 65536,
    'company_install.py': 524288,
    'company-native-retention.py': 2*1024**2,
    'company-prepare.sh': 65536,
    'company-private-quota.sh': 65536,
    'company-guided-private.sh': 40*1024,
    'installation-status.py': 131072,
    'company-request-intake.py': 786432,
    'guided-request-defaults.json': 4096,
    'company-signing-public-key.pem': 4096,
}


class IntakeUnavailable(ValueError):
    pass


def require(value, message):
    if value is not True:
        raise IntakeUnavailable(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),
                       ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')


def decode(raw, maximum):
    require(type(raw) is bytes and 0<len(raw)<=maximum,'Input is empty or exceeds its limit.')
    try:
        value=json.loads(raw)
        require(type(value) is dict and canonical(value)==raw,'Input must be one canonical object.')
    except (ValueError,TypeError,UnicodeError,RecursionError):
        raise IntakeUnavailable('Input must be one canonical object.') from None
    return value


def module(label, raw):
    name='company_request_intake_'+label+'_'+uuid.uuid4().hex
    value=ModuleType(name);value.__file__='<authenticated intake '+label+'>'
    sys.modules[name]=value
    exec(compile(raw,value.__file__,'exec'),value.__dict__)
    return value


def captured_modules(package):
    require(type(package) is dict and set(package)=={'foundation','request'},'Packaged validators are unavailable.')
    captured={}
    for name,maximum in (('foundation',524288),('request',131072)):
        row=package[name]
        require(type(row) is dict and set(row)=={'bytes','sha256','base64'},'Invalid validator capture.')
        require(type(row['bytes']) is int and 0<row['bytes']<=maximum and type(row['base64']) is str,
                'Invalid validator capture size.')
        raw=base64.b64decode(row['base64'],validate=True)
        require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'Validator capture changed.')
        captured[name]=raw
    foundation=module('foundation',captured['foundation'])
    request=module('request',captured['request'])
    row=foundation.TRUSTED_CODE['verify-release.py']
    raw=base64.b64decode(row['base64'],validate=True)
    require(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'Original key parser changed.')
    verifier=module('key_parser',raw)
    return foundation,request,verifier


def request_pair(defaults, answers, operation, foundation, request):
    require(type(operation) is str and re.fullmatch('[a-f0-9]{32}',operation) is not None
            and operation!='0'*32,'Invalid installation operation.')
    require(type(answers) is dict and set(answers)=={'dataDir','backingFile','capacityGiB'},
            'Only storage location and capacity belong in request intake.')
    common=dict(schemaVersion=1,operationId=operation,keyPath=str(PACKAGE/'company-signing-public-key.pem'),
                runscVersion=defaults['runscVersion'],runscSha512=defaults['runscSha512'],**answers)
    first=dict(common,mode='foundation-only',**defaults['foundation'])
    full=dict(common,mode='full-installation',**defaults['platform'])
    foundation.validate(first)
    # Apply the same bounded full-envelope policy to shared foundation fields.
    checked=dict(first,mode='full-installation')
    request.validate_request(canonical(checked),request_sha256=sha(canonical(checked)))
    request.validate_request(canonical(full),request_sha256=sha(canonical(full)))
    return canonical(first),canonical(full)


def validate_defaults(raw, foundation, request):
    value=decode(raw,4096)
    require(set(value)=={'schemaVersion','scope','foundation','platform','runscVersion','runscSha512'}
            and type(value['schemaVersion']) is int and value['schemaVersion']==1
            and value['scope']=='GUIDED_PRIVATE_REQUEST_DEFAULTS','Unsupported company request defaults.')
    for name in ('foundation','platform'):
        require(type(value[name]) is dict and set(value[name])=={'releaseSha256','bundleRoot','sourceRoot'},
                'Company release defaults are incomplete.')
    require(value['foundation']['releaseSha256']!=value['platform']['releaseSha256']
            and value['foundation']['bundleRoot']!=value['platform']['bundleRoot'],
            'Foundation and platform releases must be distinct.')
    request_pair(value,dict(dataDir='/srv/intake-validation',backingFile='/var/lib/intake-validation.luks',capacityGiB=32),
                 'a'*32,foundation,request)
    return value


def build(template, foundation_raw, request_raw, defaults_raw, public_key):
    """Trusted producer only; data/captures remain bound by outer delivery."""
    captures={}
    for name,raw in (('foundation',foundation_raw),('request',request_raw)):
        captures[name]=dict(bytes=len(raw),sha256=sha(raw),base64=base64.b64encode(raw).decode('ascii'))
    foundation,request,verifier=captured_modules(captures)
    validate_defaults(defaults_raw,foundation,request)
    require(sha(verifier.public_der(public_key))==foundation.COMPANY_FINGERPRINT,
            'Company public key does not match the independently bound fingerprint.')
    marker=b'PACKAGED = None  # '+b'@REQUEST_INTAKE_INPUTS@'
    require(type(template) is bytes and template.count(marker)==1,'Intake template marker is unavailable.')
    result=template.replace(marker,b'PACKAGED = '+repr(captures).encode('ascii'))
    require(len(result)<=FILES['company-request-intake.py'],'Packaged intake helper exceeds its limit.')
    return result


def delivery_receipt(records):
    require(type(records) is dict and set(records)==set(FILES),'Delivery must contain the exact intake package.')
    require(sum(map(len,records.values()))<=MAX_PACKAGE,'Delivery package exceeds its limit.')
    lines=['company-guided-delivery-v1']
    for name,raw in sorted(records.items()):
        require(type(raw) is bytes and 0<len(raw)<=FILES[name],'Delivery member exceeds its limit.')
        lines.append(name+' '+sha(raw)+' '+str(len(raw)))
    return ('\n'.join(lines)+'\n').encode('ascii')


class Inputs:
    """Read-only delivery observations, rechecked across every exclusive write."""
    def __init__(self, foundation, request, verifier, expected):
        require(type(expected) is str and re.fullmatch('[a-f0-9]{64}',expected) is not None,
                'An independently supplied delivery receipt SHA256 is required.')
        self.foundation,self.request,self.verifier=foundation,request,verifier
        self.state=foundation.NativeState();self.expected=expected;self.saved={};self.outputs={}
        self.intake_identity=None
        for path in (BASE,PACKAGE,BASE/'incoming',BASE/'staging',BASE/'evidence',REQUESTS):
            info=self.state.protected(path,True)
            require(stat.S_IMODE(info.st_mode)==0o700,'IT must prepare the protected company namespace first.')
        # The request directory's entries change through our declared exclusive
        # writes; its inode, type, ownership and mode must never change.
        self.requests_identity=foundation.identity(self.state.protected(REQUESTS,True))[:5]
        receipt=self.read(PACKAGE/'guided-delivery.txt',4096)
        require(sha(receipt)==expected,'Delivery receipt differs from the independently supplied digest.')
        records={name:self.read(PACKAGE/name,limit) for name,limit in FILES.items()}
        require(receipt==delivery_receipt(records),'Delivered files differ from the authenticated receipt.')
        require(records['company_install.py']==base64.b64decode(PACKAGED['foundation']['base64'],validate=True),
                'Intake and foundation validator origins differ.')
        self.defaults_raw=records['guided-request-defaults.json']
        self.defaults=validate_defaults(self.defaults_raw,foundation,request)
        require(sha(verifier.public_der(records['company-signing-public-key.pem']))==foundation.COMPANY_FINGERPRINT,
                'Company key differs from the independently bound fingerprint.')
        for name in ('foundation','platform'):
            row=self.defaults[name]
            self.directory(Path(row['sourceRoot']))
            release=self.read(Path(row['bundleRoot'])/'release.json',16384)
            require(sha(release)==row['releaseSha256'],'Release bytes differ from company request defaults.')
        self.recheck()

    def directory(self,path):
        info=self.state.protected(path,True)
        row=('directory',self.foundation.identity(info),None)
        require(path not in self.saved or self.saved[path]==row,'Delivered input ancestry changed between reads.')
        self.saved[path]=row
        return info

    def read(self,path,limit):
        self.state.ancestors(path)
        for parent in path.parents:
            self.directory(parent)
        before=self.state.protected(path)
        require(stat.S_IMODE(before.st_mode)==0o400,'Delivered files must be root-only mode 0400.')
        raw=self.state.read(path,limit)
        require(self.foundation.identity(before)==self.foundation.identity(self.state.protected(path)),
                'Delivered file changed during inspection.')
        prior=self.saved.get(path)
        row=('file',self.foundation.identity(before),raw)
        require(prior is None or prior==row,'Delivered input changed between reads.')
        self.saved[path]=row
        return raw

    def recheck(self):
        require(not self.foundation.UNKNOWN,'A prior descriptor close is unresolved.')
        require(self.foundation.identity(self.state.protected(REQUESTS,True))[:5]==self.requests_identity,
                'The request directory was replaced; preserve all evidence.')
        if self.intake_identity is not None:
            require(self.foundation.identity(self.state.protected(INTAKE,True))[:5]==self.intake_identity,
                    'The intake directory was replaced; preserve all evidence.')
        for path,(kind,identity,raw) in self.saved.items():
            info=self.state.protected(path,kind=='directory')
            require(self.foundation.identity(info)==identity,'Delivered input or ancestry changed; preserve all files.')
            if raw is not None:
                require(self.state.read(path,len(raw))==raw,'Delivered input bytes changed; preserve all files.')
        for path,(identity,raw) in self.outputs.items():
            require(self.foundation.identity(self.state.protected(path))==identity
                    and output_read(self,path,len(raw))==raw,'An earlier request write changed; preserve all files.')


def output_mode(path):
    # Original guided/foundation/preparation admissions require 0600 requests.
    # Content remains bound by canonical hashes, exclusive creation and identity.
    if path.parent==REQUESTS:
        require(re.fullmatch('[a-f0-9]{32}(?:\\.foundation)?\\.json',path.name) is not None,
                'Request output path is not canonical.')
        return 0o600
    require(path in (INTAKE/'intent.json',INTAKE/'complete.json'),'Request evidence path is not recognized.')
    return 0o400


def output_read(inputs,path,maximum=12288):
    state=inputs.state
    info=state.protected(path)
    require(stat.S_IMODE(info.st_mode)==output_mode(path),'Request evidence protection differs; ask IT to inspect it.')
    raw=state.read(path,maximum)
    require(inputs.foundation.identity(info)==inputs.foundation.identity(state.protected(path)),
            'Request evidence changed while reading it.')
    return raw


def record_pair(inputs, intent):
    require(set(intent)=={'schemaVersion','scope','deliverySha256','defaultsSha256','foundation','full'}
            and type(intent['schemaVersion']) is int and intent['schemaVersion']==1
            and intent['scope']=='GUIDED_PRIVATE_REQUEST_PAIR'
            and intent['deliverySha256']==inputs.expected and intent['defaultsSha256']==sha(inputs.defaults_raw),
            'Saved intake belongs to different delivery inputs; preserve it.')
    first,full=intent['foundation'],intent['full']
    require(type(first) is dict and type(full) is dict,'Saved request pair is malformed.')
    answers={key:full[key] for key in ('dataDir','backingFile','capacityGiB')}
    expected=request_pair(inputs.defaults,answers,full['operationId'],inputs.foundation,inputs.request)
    require(expected==(canonical(first),canonical(full)),'Saved requests differ from their original shared inputs.')
    return expected


def completion(intent_raw,first,full):
    return canonical(dict(schemaVersion=1,scope='GUIDED_PRIVATE_REQUEST_PAIR_COMPLETE',
        intentSha256=sha(intent_raw),foundationSha256=sha(first),fullSha256=sha(full)))


def inspect(inputs):
    """Return only an independently read complete pair; never repair partial state."""
    state=inputs.state
    inputs.recheck()
    if not state.exists(INTAKE):
        require(state.names(REQUESTS)==[],'Other request files already exist; IT must reconcile them before new intake.')
        return None
    info=state.protected(INTAKE,True)
    require(stat.S_IMODE(info.st_mode)==0o700,'Intake namespace protection differs; preserve it for IT inspection.')
    names=state.names(INTAKE)
    require(set(names)<= {'intent.json','complete.json'} and len(names)<=2,'Unexpected intake evidence; preserve it for IT inspection.')
    require('intent.json' in names,'Request creation stopped before its intent was durable. Preserve '+str(INTAKE)+'; ask IT to reconcile this empty or partial namespace.')
    raw=output_read(inputs,INTAKE/'intent.json')
    intent=decode(raw,12288);first,full=record_pair(inputs,intent)
    operation=intent['full']['operationId']
    paths=(REQUESTS/(operation+'.foundation.json'),REQUESTS/(operation+'.json'))
    missing=[str(path) for path in paths if not state.exists(path)]
    require(not missing,'Request creation is incomplete. Missing: '+', '.join(missing)+'. Preserve all existing files; IT must reconcile the pair. No files were replayed.')
    require(output_read(inputs,paths[0],4096)==first and output_read(inputs,paths[1],4096)==full,
            'Saved request bytes differ; preserve both files and ask IT to reconcile them.')
    require('complete.json' in names,'Both requests exist but completion was not confirmed. Preserve them; ask IT to verify the interrupted intake. Do not repeat creation.')
    require(output_read(inputs,INTAKE/'complete.json')==completion(raw,first,full),
            'Request completion evidence differs; preserve all records for IT inspection.')
    require(state.names(REQUESTS)==sorted(['intake',paths[0].name,paths[1].name]),
            'Additional request files need IT reconciliation before continuing.')
    require(output_read(inputs,INTAKE/'intent.json')==raw and state.names(INTAKE)==names
            and inputs.foundation.identity(state.protected(INTAKE,True))==inputs.foundation.identity(info),
            'Intake evidence changed while checking it.')
    inputs.recheck()
    return paths


def collect(inputs):
    """Storage prompts only. The existing configuration wizard owns all secrets."""
    def ask(label,default):
        value=input(label+' ['+default+']: ').strip() or default
        require(0<len(value)<=1024 and '\0' not in value,'The storage answer is empty or too long.')
        return value
    print('Prepare Doxentriq setup inputs. Your IT installer chooses the storage locations below.')
    answers=dict(dataDir=ask('Folder where encrypted Doxentriq data will be mounted','/srv/autosoft'),
                 backingFile=ask('New file that will hold the encrypted data','/var/lib/autosoft-data.luks'))
    capacity=ask('Disk space to reserve in GiB (32 through 4096)','64')
    require(re.fullmatch('[1-9][0-9]{1,3}',capacity) is not None and 32<=int(capacity)<=4096,
            'Enter a whole capacity from 32 through 4096 GiB.')
    answers['capacityGiB']=int(capacity)
    first,full=request_pair(inputs.defaults,answers,uuid.uuid4().hex,inputs.foundation,inputs.request)
    require(not inputs.state.exists(answers['backingFile']),
            'The backing-file path already exists. Intake will not overwrite or adopt it.')
    require(not inputs.state.exists(answers['dataDir']),
            'The data mount already exists. Ask IT to reconcile prior installation state before continuing.')
    print('These inputs describe a new '+str(answers['capacityGiB'])+' GiB encrypted volume at '+answers['backingFile']+'.')
    print('This step writes request files only. It does not format a volume or start installation.')
    return first,full


def write_exclusive(inputs,path,raw):
    inputs.recheck()
    state=inputs.state;state.ancestors(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,output_mode(path))
    try:
        offset=0
        while offset<len(raw):
            count=os.write(fd,raw[offset:offset+65536])
            require(type(count) is int and 0<count<=len(raw)-offset,'Request write stopped; preserve partial evidence.')
            offset+=count
        os.fsync(fd)
    finally:
        try:os.close(fd)
        except BaseException:inputs.foundation.UNKNOWN.append((path,fd));raise
    state.sync(path.parent)
    require(output_read(inputs,path)==raw,'Written request did not match readback; preserve all files.')
    inputs.outputs[path]=(inputs.foundation.identity(state.protected(path)),raw)
    inputs.recheck()


def prepare(inputs,answers=None):
    existing=inspect(inputs)
    if existing is not None:
        print('Setup inputs already exist and were verified. No prompts or installation steps were repeated.')
        return existing
    first,full=collect(inputs) if answers is None else answers
    values=(decode(first,4096),decode(full,4096))
    intent=canonical(dict(schemaVersion=1,scope='GUIDED_PRIVATE_REQUEST_PAIR',deliverySha256=inputs.expected,
        defaultsSha256=sha(inputs.defaults_raw),foundation=values[0],full=values[1]))
    record_pair(inputs,decode(intent,12288))
    # Recheck fresh state after prompts and before the first durable effect.
    require(inspect(inputs) is None,'Another intake completed while prompts were open; use read-only status.')
    inputs.state.mkdir(INTAKE)
    inputs.intake_identity=inputs.foundation.identity(inputs.state.protected(INTAKE,True))[:5]
    write_exclusive(inputs,INTAKE/'intent.json',intent)
    operation=values[1]['operationId']
    write_exclusive(inputs,REQUESTS/(operation+'.foundation.json'),first)
    write_exclusive(inputs,REQUESTS/(operation+'.json'),full)
    write_exclusive(inputs,INTAKE/'complete.json',completion(intent,first,full))
    return inspect(inputs)


def show_next(paths):
    if paths is None:
        print('No setup input pair exists. Use --prepare-requests with the independently supplied delivery digest.')
        return
    print('Doxentriq setup inputs are ready. To start private setup:')
    print('sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C LANG=C HOME=/ TZ=UTC '
          '/bin/bash --noprofile --norc '+str(PACKAGE/'company-guided-private.sh')+
          ' --install-private '+str(paths[0])+' '+str(paths[1]))
    print('This development preview keeps the public website disabled until the remaining installation checks are complete.')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('collect','status'))
    parser.add_argument('--delivery-sha256',required=True)
    args=parser.parse_args(argv)
    foundation,request,verifier=captured_modules(PACKAGED)
    inputs=Inputs(foundation,request,verifier,args.delivery_sha256)
    show_next(prepare(inputs) if args.command=='collect' else inspect(inputs))


if __name__=='__main__':
    try:main()
    except BaseException as error:
        print('Doxentriq setup input preparation stopped. '+(str(error) if isinstance(error,IntakeUnavailable) else
              'Keep the delivery and request files; ask IT to inspect the interrupted step.'),file=sys.stderr)
        print('Read-only guidance: company-guided-private.sh --request-status RECEIPT_SHA256',file=sys.stderr)
        sys.exit(74)

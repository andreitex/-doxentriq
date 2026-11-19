"""Build a pre-Python delivery placer from the original closed guided package.

The company authenticates this new entry independently. Its embedded package
pins do not make initial executing code trustworthy. This producer grants no
installation or package eligibility authority and performs no host effects.
"""
import hashlib
import re

MAX_ENTRY=40*1024


def require(value,reason):
    if not value:raise ValueError(reason)


def build(template,lock,records,*,intake):
    """The authenticated company producer supplies the original intake module."""
    require(type(template)is bytes and 0<len(template)<=24*1024,'placement-template-size')
    require(type(lock)is bytes and 0<len(lock)<=32*1024,'placement-lock-size')
    require(type(records)is dict and set(records)==set(intake.FILES)|{'guided-delivery.txt'},'placement-exact-package-required')
    delivered={name:records[name]for name in intake.FILES}
    require(records['guided-delivery.txt']==intake.delivery_receipt(delivered),'placement-receipt-binding')
    require(type(records['guided-delivery.txt'])is bytes and 0<len(records['guided-delivery.txt'])<=4096,'placement-receipt-size')
    for name,limit in {**intake.FILES,'guided-delivery.txt':4096}.items():
        require(type(name)is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,63}',name)is not None,'placement-fixed-member-name')
        require(type(records[name])is bytes and 0<len(records[name])<=limit,'placement-member-size')
    markers=(b'# @EMBED_INSTALL_LOCK@',b'@BOOTSTRAP_RECEIPT_SHA256@',b'@BOOTSTRAP_TOTAL_BYTES@',b'# @BOOTSTRAP_FILE_TABLE@')
    require(all(template.count(marker)==1 for marker in markers),'placement-template-marker')
    total=sum(map(len,records.values()));require(total<=intake.MAX_PACKAGE+4096,'placement-package-size')
    lines='\n'.join('  "$1" '+name+' '+str(len(raw))+' '+hashlib.sha256(raw).hexdigest()for name,raw in sorted(records.items())).encode('ascii')
    result=template.replace(markers[0],lock).replace(markers[1],hashlib.sha256(records['guided-delivery.txt']).hexdigest().encode())
    result=result.replace(markers[2],str(total).encode()).replace(markers[3],lines)
    require(len(result)<=MAX_ENTRY,'placement-entry-size')
    return result

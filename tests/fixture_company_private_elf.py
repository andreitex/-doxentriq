"""Synthetic ELF data only; these bytes must never be executed."""
import struct

LIBRARY = '/usr/lib64/doxentriq-runtime/libseccomp.so.2'


def linkage():
    return dict(schemaVersion=1, scope='COMPANY_PRIVATE_SECCOMP_ELF_CONTRACT',
        runc=dict(path='/usr/bin/runc', needed=['libc.so.6','libseccomp.so.2'],
                  interpreter='/lib64/ld-linux-x86-64.so.2',runpath='/usr/lib64/doxentriq-runtime'),
        library=dict(path=LIBRARY,needed=['libc.so.6'],soname='libseccomp.so.2'))


def elf(role, *, needed=None):
    base=0x400000; raw=bytearray(4096); strings=bytearray(b'\0'); offsets={}
    if needed is None:needed=linkage()[role]['needed']
    for value in dict.fromkeys(('libc.so.6','libseccomp.so.2','/usr/lib64/doxentriq-runtime',*needed)):
        offsets[value]=len(strings);strings.extend(value.encode()+b'\0')
    tags=[(1,offsets[x]) for x in needed]+[(5,base+1024),(10,len(strings)),(6,base+1536),(11,24),(30,8),
        (29,offsets['/usr/lib64/doxentriq-runtime']) if role=='runc' else (14,offsets['libseccomp.so.2']),(0,0)]
    dynamic=b''.join(struct.pack('<qQ',*x) for x in tags)
    interp=b'/lib64/ld-linux-x86-64.so.2\0'
    segments=[(1,5,0,base,base,len(raw),len(raw),4096),
              (2,4,512,base+512,base+512,len(dynamic),len(dynamic),8),
              (0x6474e551,6,0,0,0,0,0,16),
              (0x6474e552,4,512,base+512,base+512,len(dynamic),len(dynamic),1)]
    if role=='runc':segments.append((3,4,400,base+400,base+400,len(interp),len(interp),1))
    raw[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',raw,16,3,62,1,base+1800 if role=='runc' else 0,64,0,0,64,56,len(segments),0,0,0)
    for n,row in enumerate(segments):struct.pack_into('<IIQQQQQQ',raw,64+n*56,*row)
    raw[400:400+len(interp)]=interp;raw[512:512+len(dynamic)]=dynamic;raw[1024:1024+len(strings)]=strings
    return bytes(raw)


def tag_change(raw, tag, *, new_tag=None, new_value=None):
    data=bytearray(raw)
    for offset in range(512,1024,16):
        current,value=struct.unpack_from('<qQ',data,offset)
        if current==tag:
            struct.pack_into('<qQ',data,offset,current if new_tag is None else new_tag,value if new_value is None else new_value)
            return bytes(data)
        if current==0:break
    raise ValueError('Synthetic tag absent')

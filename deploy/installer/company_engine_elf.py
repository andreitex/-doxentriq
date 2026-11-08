"""Bounded ELF data checks; no loader, execution, signing or qualification authority."""
import hashlib
import struct

LIBRARY = '/usr/lib64/doxentriq-runtime/libseccomp.so.2'
RUNPATH = '/usr/lib64/doxentriq-runtime'
INTERPRETER = '/lib64/ld-linux-x86-64.so.2'
RUNC_NEEDED = frozenset(('libseccomp.so.2', 'libc.so.6', 'libgcc_s.so.1', 'libm.so.6',
                        'libdl.so.2', 'libpthread.so.0', 'librt.so.1', 'libresolv.so.2',
                        'ld-linux-x86-64.so.2'))
# libpathrs may reference the loader's versioned __tls_get_addr symbol. This
# permits that exact SONAME, not a new interpreter or an inferred dependency:
# the authenticated payload must still name every actual DT_NEEDED entry.
TAGS = frozenset((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30,
                 32, 33, 34, 35, 36, 37, 0x6ffffef5, 0x6ffffff0,
                 0x6ffffff9, 0x6ffffffa, 0x6ffffffb, 0x6ffffffc,
                 0x6ffffffd, 0x6ffffffe, 0x6fffffff))
PH_TYPES = frozenset((0, 1, 2, 3, 4, 6, 7, 0x6474e550, 0x6474e551, 0x6474e552, 0x6474e553))


def require(value, reason='Company private library ELF contract refused'):
    if not value:
        raise ValueError(reason)


def contract(value):
    require(type(value) is dict and set(value) == {'schemaVersion', 'scope', 'runc', 'library'})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1 and
            value['scope'] == 'COMPANY_PRIVATE_SECCOMP_ELF_CONTRACT')
    r, l = value['runc'], value['library']
    require(type(r) is dict and set(r) == {'path', 'needed', 'interpreter', 'runpath'} and
            r['path'] == '/usr/bin/runc' and r['interpreter'] == INTERPRETER and r['runpath'] == RUNPATH)
    require(type(r['needed']) is list and all(type(x) is str for x in r['needed']) and
            r['needed'] == sorted(set(r['needed'])) and {'libseccomp.so.2', 'libc.so.6'} <= set(r['needed']) <= RUNC_NEEDED)
    require(type(l) is dict and set(l) == {'path', 'needed', 'soname'} and
            l['path'] == LIBRARY and l['needed'] == ['libc.so.6'] and l['soname'] == 'libseccomp.so.2')
    return value


def _elf(raw, role, expected):
    require(type(raw) is bytes and 64 <= len(raw) <= (256 if role == 'runc' else 32)*1024**2)
    def span(offset, size):
        require(type(offset) is int and type(size) is int and 0 <= offset <= len(raw) and 0 <= size <= len(raw)-offset, 'ELF file range')
        return raw[offset:offset+size]
    ident = span(0, 16)
    require(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3) and ident[8:] == b'\0'*8, 'ELF identification')
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstr = struct.unpack('<HHIQQQIHHHHHH', span(16,48))
    require(kind == 3 and machine == 62 and version == 1 and flags == 0 and ehsize == 64 and phentsize == 56 and 1 <= phnum <= 32, 'ELF header')
    require(phoff >= 64 and phoff % 8 == 0, 'ELF program table')
    span(phoff, phnum*56)
    if shoff:
        require(shoff % 8 == 0 and shentsize == 64 and 1 <= shnum <= 65534 and 0 <= shstr < shnum, 'ELF section table')
        span(shoff, shnum*64)
        for n in range(shnum):
            _, section_type, _, address, offset, size, link, _, alignment, entsize = struct.unpack('<IIQQQQIIQQ', span(shoff+n*64,64))
            require(address < 1<<63 and size <= (1<<63)-address and link < shnum and (alignment in (0,1) or alignment <= 1<<30 and alignment & (alignment-1) == 0), 'ELF section metadata')
            require(entsize == 0 or size % entsize == 0, 'ELF section element size')
            if section_type != 8: span(offset,size)
    else:
        require(shnum == shentsize == shstr == 0, 'ELF omitted section table')
    segments=[]
    for n in range(phnum):
        tag, perms, offset, address, physical, filesz, memsz, alignment = struct.unpack('<IIQQQQQQ', span(phoff+n*56,56))
        require(tag in PH_TYPES and not perms & ~7 and address < 1<<63 and physical < 1<<63 and
                memsz <= (1<<63)-address and filesz <= memsz and (alignment in (0,1) or alignment <= 1<<30 and alignment & (alignment-1) == 0), 'ELF segment metadata')
        span(offset,filesz)
        if tag == 1:
            require(not (perms & 2 and perms & 1) and (alignment <= 1 or address % alignment == offset % alignment), 'ELF load segment')
        segments.append(dict(tag=tag, flags=perms, offset=offset, address=address, filesz=filesz, memsz=memsz))
    loads=[x for x in segments if x['tag']==1]
    require(loads and len(loads)<=8, 'ELF load inventory')
    def mapped(address,size):
        matches=[x for x in loads if x['address']<=address and size<=x['filesz']-(address-x['address'])]
        require(len(matches)==1, 'ELF virtual mapping')
        x=matches[0]
        return x['offset']+address-x['address']
    stack=[x for x in segments if x['tag']==0x6474e551]
    relro=[x for x in segments if x['tag']==0x6474e552]
    dynamic=[x for x in segments if x['tag']==2]
    interpreter=[x for x in segments if x['tag']==3]
    require(len(stack)==len(relro)==len(dynamic)==1 and stack[0]['flags']==6 and relro[0]['memsz']>0, 'ELF NX/RELRO/dynamic inventory')
    d=dynamic[0]
    require(16<=d['filesz']<=65536 and d['filesz']%16==0 and mapped(d['address'],d['filesz'])==d['offset'], 'ELF dynamic mapping')
    require(relro[0]['address']<=d['address'] and d['filesz']<=relro[0]['memsz']-(d['address']-relro[0]['address']), 'ELF dynamic RELRO coverage')
    if role=='runc':
        require(len(interpreter)==1 and span(interpreter[0]['offset'],interpreter[0]['filesz'])==INTERPRETER.encode()+b'\0', 'ELF interpreter')
        require(any(x['flags']&1 and x['address']<=entry<x['address']+x['memsz'] for x in loads), 'ELF entry point')
    else:
        require(not interpreter and entry==0, 'ELF shared library entry/interpreter')
    tags={}; terminated=False
    for offset in range(d['offset'],d['offset']+d['filesz'],16):
        tag,value=struct.unpack('<qQ',span(offset,16))
        if terminated:
            require(tag==value==0, 'ELF dynamic tail')
            continue
        require(tag in TAGS, 'ELF unsupported loader tag')
        if tag==0:
            require(value==0, 'ELF dynamic terminator');terminated=True;continue
        require(tag==1 or tag not in tags, 'ELF duplicate dynamic tag')
        tags.setdefault(tag,[]).append(value)
    require(terminated and 5 in tags and 10 in tags and 1 in tags, 'ELF required dynamic tags')
    require(6 in tags and tags.get(11)==[24], 'ELF symbol table layout')
    mapped(tags[6][0],24)
    # Dynamic addresses are virtual addresses, never unchecked file offsets.
    for tag, minimum in ((3,8),(4,8),(0x6ffffef5,16),(0x6ffffff0,2),
                         (0x6ffffffc,20),(0x6ffffffe,16),(34,4)):
        if tag in tags: mapped(tags[tag][0],minimum)
    for pointer, size_tag, entry_tag, width in ((7,8,9,24),(17,18,19,16),(36,35,37,8)):
        if any(x in tags for x in (pointer,size_tag,entry_tag)):
            require(all(x in tags for x in (pointer,size_tag,entry_tag)) and tags[entry_tag]==[width]
                    and tags[size_tag][0] % width == 0,'ELF relocation table layout')
            mapped(tags[pointer][0],tags[size_tag][0])
    for pointer, size_tag in ((25,27),(26,28),(32,33)):
        if pointer in tags or size_tag in tags:
            require(pointer in tags and size_tag in tags and tags[size_tag][0]%8==0,'ELF callback array layout')
            mapped(tags[pointer][0],tags[size_tag][0])
    if any(x in tags for x in (2,20,23)):
        require(all(x in tags for x in (2,20,23)) and tags[20][0] in (7,17) and
                tags[2][0] % (24 if tags[20][0]==7 else 16)==0,'ELF PLT relocation layout')
        mapped(tags[23][0],tags[2][0])
    for tag in (12,13):
        if tag in tags and tags[tag][0]:
            address=tags[tag][0];mapped(address,1)
            require(any(x['flags']&1 and x['address']<=address<x['address']+x['filesz'] for x in loads),'ELF callback address')
    require(21 not in tags or tags[21]==[0],'ELF preinitialized debug loader state')
    size=tags[10][0]; require(1<=size<=4<<20,'ELF string table bound')
    strings=span(mapped(tags[5][0],size),size)
    def string(index):
        require(0<=index<len(strings),'ELF string offset')
        end=strings.find(b'\0',index,min(len(strings),index+257));require(end>=index,'ELF string termination')
        value=strings[index:end];require(value and all(32<=x<=126 for x in value),'ELF string characters')
        return value.decode('ascii')
    needed=[string(x) for x in tags[1]]
    require(len(needed)==len(set(needed)) and sorted(needed)==expected['needed'],'ELF NEEDED differs from authenticated expectation')
    require(not tags.get(30,[0])[0]&~(8|16) and not tags.get(0x6ffffffb,[0])[0]&~(1|0x08000000), 'ELF dynamic loader flags')
    require(24 in tags or tags.get(30,[0])[0]&8 or tags.get(0x6ffffffb,[0])[0]&1,'ELF immediate binding')
    if role=='runc':
        require(29 in tags and string(tags[29][0])==RUNPATH and 14 not in tags,'ELF runc RUNPATH/SONAME')
    else:
        require(29 not in tags and 14 in tags and string(tags[14][0])=='libseccomp.so.2','ELF private SONAME/RUNPATH')
    return dict(path=expected['path'],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),needed=sorted(needed),
                nxStack=True,relro=True,immediateBinding=True,interpreter=INTERPRETER if role=='runc' else None,
                runpath=RUNPATH if role=='runc' else None,soname='libseccomp.so.2' if role=='library' else None)


def verify_pair(runc, library, expected):
    """Expected data must come from the already-held authenticated v2 payload.

    This data-only function cannot authenticate its caller or grant installation
    authority. Exact hashes and the signed company manifest establish that outer
    boundary. It never invokes the host loader or any target executable.
    """
    contract(expected)
    return dict(scope='COMPANY_PRIVATE_LIBRARY_ELF_DATA_ONLY',
        runc=_elf(runc,'runc',expected['runc']),library=_elf(library,'library',expected['library']),
        payloadExecuted=False,abiQualified=False,securityQualified=False)

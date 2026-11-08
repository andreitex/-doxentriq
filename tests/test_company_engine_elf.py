"""Malformed ELF refusal tests operate on inert synthetic data only."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
E=load('company_private_elf',ROOT/'deploy/installer/company_engine_elf.py')
F=load('company_private_elf_fixture',ROOT/'tests/fixture_company_private_elf.py')


class ElfContract(unittest.TestCase):
    def verify(self,runc=None,library=None,expected=None):
        return E.verify_pair(F.elf('runc') if runc is None else runc,F.elf('library') if library is None else library,F.linkage() if expected is None else expected)

    def test_exact_pair_data_only(self):
        result=self.verify()
        self.assertFalse(result['payloadExecuted']);self.assertFalse(result['abiQualified'])
        self.assertEqual(result['runc']['runpath'],'/usr/lib64/doxentriq-runtime')
        self.assertEqual(result['library']['soname'],'libseccomp.so.2')

    def test_expected_dependencies_are_not_inferred(self):
        for needed in (['libc.so.6'],['libc.so.6','libevil.so.1','libseccomp.so.2'],['libc.so.6','libseccomp.so.2','libseccomp.so.2']):
            value=F.linkage();value['runc']['needed']=needed
            with self.assertRaises(ValueError):self.verify(expected=value)
        value=F.linkage();value['runc']['needed']=['libc.so.6','libm.so.6','libseccomp.so.2']
        with self.assertRaisesRegex(ValueError,'NEEDED'):self.verify(expected=value)

    def test_library_contract_cannot_add_runtime_dependencies(self):
        value=F.linkage();value['library']['needed']=['libc.so.6','libm.so.6']
        with self.assertRaises(ValueError):self.verify(expected=value)

    def test_loader_soname_requires_exact_authenticated_dependency_set(self):
        expected=F.linkage()
        needed=['ld-linux-x86-64.so.2','libc.so.6','libgcc_s.so.1','libm.so.6','libresolv.so.2','libseccomp.so.2']
        expected['runc']['needed']=needed
        raw=F.elf('runc',needed=needed)
        result=self.verify(runc=raw,expected=expected)
        self.assertEqual(result['runc']['needed'],needed)
        self.assertEqual(result['runc']['interpreter'],'/lib64/ld-linux-x86-64.so.2')
        self.assertFalse(result['abiQualified']);self.assertFalse(result['securityQualified'])
        with self.assertRaisesRegex(ValueError,'NEEDED'):self.verify(runc=raw)
        with self.assertRaisesRegex(ValueError,'NEEDED'):self.verify(expected=expected)

    def test_loader_soname_does_not_allow_paths_alternates_or_library_dependency(self):
        for name in ('/lib64/ld-linux-x86-64.so.2','ld-linux-x86-64.so.3','ld-linux-aarch64.so.1','../ld-linux-x86-64.so.2'):
            expected=F.linkage();expected['runc']['needed']=sorted([*expected['runc']['needed'],name])
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.verify(runc=F.elf('runc',needed=expected['runc']['needed']),expected=expected)
        expected=F.linkage();expected['library']['needed']=['ld-linux-x86-64.so.2','libc.so.6']
        with self.assertRaises(ValueError):
            self.verify(library=F.elf('library',needed=expected['library']['needed']),expected=expected)

    def test_header_and_table_offsets(self):
        for offset,fmt,value in ((18,'H',183),(32,'Q',2**64-1),(54,'H',55),(56,'H',65535),(40,'Q',4000),(20,'I',2)):
            raw=bytearray(F.elf('runc'));struct.pack_into('<'+fmt,raw,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):self.verify(runc=bytes(raw))
        for raw in (b'',b'\x7fELF',F.elf('runc')[:-1]):
            with self.assertRaises(ValueError):self.verify(runc=raw)

    def test_malformed_dynamic_offsets_strings_and_duplicates(self):
        for tag,value in ((5,2**64-1),(10,2**32),(1,2**32),(11,23)):
            raw=F.tag_change(F.elf('runc'),tag,new_value=value)
            with self.subTest(tag=tag),self.assertRaises(ValueError):self.verify(runc=raw)
        raw=F.tag_change(F.elf('runc'),11,new_tag=10)
        with self.assertRaises(ValueError):self.verify(runc=raw)

    def test_loader_audit_filter_rpath_and_unknown_tags(self):
        for tag in (15,22,0x6ffffefb,0x6ffffefc,0x7fffffff,0x7ffffffd,123456):
            raw=F.tag_change(F.elf('runc'),29,new_tag=tag)
            with self.subTest(tag=tag),self.assertRaises(ValueError):self.verify(runc=raw)

    def test_no_execstack_writable_code_or_missing_relro(self):
        for offset,value in ((64+2*56+4,7),(64+4,7),(64+3*56,0)):
            raw=bytearray(F.elf('runc'));struct.pack_into('<I',raw,offset,value)
            with self.assertRaises(ValueError):self.verify(runc=bytes(raw))

    def test_exact_interpreter_soname_runpath(self):
        for before,after in ((b'/lib64/ld-linux-x86-64.so.2',b'/tmpxx/ld-linux-x86-64.so.2'),(b'/usr/lib64/doxentriq-runtime',b'$ORIGIN/xx/doxentriq-runtime')):
            self.assertEqual(len(before),len(after))
            with self.assertRaises(ValueError):self.verify(runc=F.elf('runc').replace(before,after))
        with self.assertRaises(ValueError):self.verify(library=F.elf('library').replace(b'libseccomp.so.2',b'libseccomp.so.3'))
        with self.assertRaises(ValueError):self.verify(library=F.tag_change(F.elf('library'),14,new_tag=29))

    def test_now_binding_and_unsupported_flags(self):
        for value in (0,4,0x80000000):
            with self.assertRaises(ValueError):self.verify(runc=F.tag_change(F.elf('runc'),30,new_value=value))

    def test_nested_contract_extra_or_wrong_types(self):
        for mutate in (lambda x:x.update(schemaVersion=True),lambda x:x['runc'].update(extra='x'),
                       lambda x:x['runc'].update(runpath='/usr/lib64'),lambda x:x['library'].update(path='/usr/lib64/libseccomp.so.2')):
            value=F.linkage();mutate(value)
            with self.assertRaises(ValueError):self.verify(expected=value)


if __name__=='__main__':unittest.main(verbosity=2)

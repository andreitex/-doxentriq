import hashlib,importlib.util,json,urllib.error
from pathlib import Path
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('registry_manifest',Path(__file__).with_name('registry_manifest.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class RegistryManifest(unittest.TestCase):
    def fixture(self,mutate=None):
        config=dict(architecture='amd64',os='linux',rootfs=dict(type='layers',diff_ids=['sha256:'+'a'*64]))
        blob=json.dumps(config).encode();identity='sha256:'+hashlib.sha256(blob).hexdigest()
        manifest=dict(schemaVersion=2,mediaType='application/vnd.oci.image.manifest.v1+json',config=dict(digest=identity,size=len(blob)),layers=[dict(digest='sha256:'+'b'*64,size=80)])
        if mutate:mutate(manifest,config)
        body=json.dumps(manifest).encode()
        replies={
            '/v2/company/base/manifests/release':(body,{'Docker-Content-Digest':'sha256:'+hashlib.sha256(body).hexdigest(),'Content-Type':manifest['mediaType']}),
            '/v2/company/base/blobs/'+identity:(blob,{'Docker-Content-Digest':identity}),
            '/v2/company/base/blobs/sha256:'+'b'*64:(b'',{'Docker-Content-Digest':'sha256:'+'b'*64,'Content-Length':'80'})}
        class Client:
            def request(self,path,method='GET',limit=2<<20):return replies[path]
        local=dict(Id=identity,Architecture='amd64',Os='linux',RootFS=dict(Layers=config['rootfs']['diff_ids']),RepoDigests=['registry.test/company/base@sha256:'+'f'*64])
        return local,Client(),replies

    def test_multiarch_repo_digest_is_never_trusted(self):
        local,client,_=self.fixture();result=module.qualify('registry.test/company/base:release',local,client)
        self.assertNotEqual(result['reference'],local['RepoDigests'][0]);self.assertTrue(result['verifiedTLS'])
        self.assertEqual(result['sourceConfigId'],local['Id'])

    def containerd_fixture(self):
        local,client,replies=self.fixture()
        config_id=local['Id'];body,headers=replies['/v2/company/base/manifests/release']
        local['Id']=headers['Docker-Content-Digest']
        local['Descriptor']=dict(mediaType='application/vnd.oci.image.manifest.v1+json',digest=local['Id'],size=len(body),platform=dict(os='linux',architecture='amd64'))
        return local,client,replies,config_id

    def test_docker29_manifest_id_binds_target_bytes_and_config(self):
        local,client,_,config_id=self.containerd_fixture()
        result=module.qualify('registry.test/company/base:release',local,client)
        self.assertEqual(result['sourceIdentityMode'],'platform-manifest')
        self.assertEqual(result['sourceManifestDigest'],local['Id'])
        self.assertEqual(result['sourceConfigId'],config_id)
        self.assertNotEqual(config_id,local['Id'])

    def test_real_inspection_always_selects_linux_amd64(self):
        local,client,_,_=self.containerd_fixture()
        with patch.object(module.subprocess,'check_output',return_value=json.dumps([local])) as inspect:
            module.qualify('registry.test/company/base:release',client=client)
        self.assertEqual(inspect.call_args.args[0],['docker','image','inspect','--platform','linux/amd64','registry.test/company/base:release'])

    def test_docker29_optional_config_annotation_is_verified(self):
        local,client,_,config_id=self.containerd_fixture();local['Descriptor']['annotations']={'config.digest':config_id}
        self.assertEqual(module.qualify('registry.test/company/base:release',local,client)['sourceConfigId'],config_id)

    def test_docker29_stale_descriptor_is_rejected(self):
        local,client,_,_=self.containerd_fixture();local['Descriptor']['digest']='sha256:'+'f'*64
        with self.assertRaisesRegex(ValueError,'source manifest'):module.qualify('registry.test/company/base:release',local,client)

    def test_docker29_index_descriptor_cannot_masquerade_as_platform(self):
        local,client,_,_=self.containerd_fixture();local['Descriptor']['mediaType']='application/vnd.oci.image.index.v1+json'
        with self.assertRaisesRegex(ValueError,'source manifest'):module.qualify('registry.test/company/base:release',local,client)

    def test_docker29_same_diffids_with_changed_manifest_is_rejected(self):
        local,client,replies,_=self.containerd_fixture()
        manifest=json.loads(replies['/v2/company/base/manifests/release'][0]);manifest['annotations']={'untrusted':'change'}
        body=json.dumps(manifest).encode();replies['/v2/company/base/manifests/release']=(body,{'Docker-Content-Digest':'sha256:'+hashlib.sha256(body).hexdigest(),'Content-Type':manifest['mediaType']})
        with self.assertRaisesRegex(ValueError,'manifest bytes differ'):module.qualify('registry.test/company/base:release',local,client)

    def test_docker29_foreign_selected_platform_is_rejected(self):
        local,client,_,_=self.containerd_fixture();local['Descriptor']['platform']['architecture']='arm64'
        with self.assertRaisesRegex(ValueError,'platform differs'):module.qualify('registry.test/company/base:release',local,client)

    def test_docker29_config_annotation_substitution_is_rejected(self):
        local,client,_,_=self.containerd_fixture();local['Descriptor']['annotations']={'config.digest':'sha256:'+'f'*64}
        with self.assertRaisesRegex(ValueError,'annotation differs'):module.qualify('registry.test/company/base:release',local,client)

    def test_unavailable_target_manifest_is_rejected(self):
        local,client,replies=self.fixture();replies.clear()
        with self.assertRaises(KeyError):module.qualify('registry.test/company/base:release',local,client)

    def test_manifest_digest_header_rewrite_is_rejected(self):
        local,client,replies=self.fixture();replies['/v2/company/base/manifests/release'][1]['Docker-Content-Digest']='sha256:'+'f'*64
        with self.assertRaises(ValueError):module.qualify('registry.test/company/base:release',local,client)

    def test_target_config_substitution_is_rejected(self):
        local,client,_=self.fixture(lambda manifest,config:manifest['config'].update(digest='sha256:'+'f'*64))
        with self.assertRaises(ValueError):module.qualify('registry.test/company/base:release',local,client)

    def test_config_blob_mutation_is_rejected(self):
        local,client,replies=self.fixture();replies['/v2/company/base/blobs/'+local['Id']]=(b'{}',{'Docker-Content-Digest':local['Id']})
        with self.assertRaises(ValueError):module.qualify('registry.test/company/base:release',local,client)

    def test_source_foreign_architecture_is_rejected(self):
        local,client,_=self.fixture();local['Architecture']='arm64'
        with self.assertRaises(ValueError):module.qualify('registry.test/company/base:release',local,client)

    def test_target_index_instead_of_manifest_is_rejected(self):
        local,client,_=self.fixture(lambda manifest,config:manifest.update(mediaType='application/vnd.oci.image.index.v1+json'))
        with self.assertRaises(ValueError):module.qualify('registry.test/company/base:release',local,client)

    def test_missing_or_changed_layer_is_rejected(self):
        local,client,replies=self.fixture();replies['/v2/company/base/blobs/sha256:'+'b'*64][1]['Content-Length']='79'
        with self.assertRaises(ValueError):module.qualify('registry.test/company/base:release',local,client)

    def test_redirect_is_rejected_without_following(self):
        with self.assertRaises(ValueError):module.NoRedirect().redirect_request(None,None,307,'',{},'https://unrelated.test/blob')

    def test_non_200_manifest_response_is_rejected(self):
        class Response:
            status=201
            def __enter__(self):return self
            def __exit__(self,*_args):pass
        class Opener:
            def open(self,*_args,**_kwargs):return Response()
        client=module.Registry.__new__(module.Registry);client.host='registry.test';client.repository='company/base';client.authorization=None;client.opener=Opener()
        with self.assertRaisesRegex(ValueError,'HTTP 200'):client.request('/v2/company/base/manifests/release')

    def test_bearer_credentials_never_leave_registry_authority(self):
        class Opener:
            calls=0
            def open(self,request,**_kwargs):
                self.calls+=1
                raise urllib.error.HTTPError(request.full_url,401,'',{'WWW-Authenticate':'Bearer realm="https://unrelated.test/token",service="registry.test"'},None)
        client=module.Registry.__new__(module.Registry);client.host='registry.test';client.repository='company/base';client.authorization='Basic synthetic';client.opener=Opener()
        with self.assertRaisesRegex(ValueError,'authority'):client.request('/v2/company/base/manifests/release')
        self.assertEqual(client.opener.calls,1)

    def test_non_200_scoped_token_response_is_rejected(self):
        class Response:
            status=201
            def __enter__(self):return self
            def __exit__(self,*_args):pass
        class Opener:
            calls=0
            def open(self,request,**_kwargs):
                self.calls+=1
                if self.calls==1:raise urllib.error.HTTPError(request.full_url,401,'',{'WWW-Authenticate':'Bearer realm="https://registry.test/token",service="registry.test"'},None)
                return Response()
        client=module.Registry.__new__(module.Registry);client.host='registry.test';client.repository='company/base';client.authorization='Basic synthetic';client.opener=Opener()
        with self.assertRaisesRegex(ValueError,'HTTP 200'):client.request('/v2/company/base/manifests/release')

if __name__=='__main__':unittest.main()

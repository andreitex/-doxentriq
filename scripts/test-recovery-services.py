#!/usr/bin/env python3
"""Cold recovery must remain isolated and never authorize production switching."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import recovery_services as stores

CID = 'a'*64
IMAGE_ID = 'sha256:' + 'b'*64
IMAGE = 'company/redis@sha256:' + 'c'*64


class ColdStoreTests(unittest.TestCase):
    def setUp(self):
        local = Path(__file__).resolve().parent.parent / '.local'
        local.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=local)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.candidate, self.inputs = self.root/'candidate', self.root/'inputs'
        self.inputs.mkdir(); self.candidate.mkdir()
        for folder in ['redis','rabbitmq','secrets/runtime']:
            (self.candidate/folder).mkdir(parents=True, exist_ok=True)
        (self.candidate/'secrets/runtime/redis-admin').write_text('synthetic-protected-password')

    def record(self, service):
        target = '/data' if service == 'redis' else '/var/lib/rabbitmq'
        config = '/run/restore/redis.conf' if service == 'redis' else '/etc/rabbitmq/rabbitmq.conf'
        return dict(Id=CID,Image=IMAGE_ID,Name='/autosoft-store-0123456789ab-'+service,
            Config=dict(Image=IMAGE,User='999:999',Hostname='rabbitmq',Env=['RABBITMQ_NODENAME=rabbit@rabbitmq'],
                        Cmd=['redis-server',config] if service=='redis' else ['rabbitmq-server']),
            State=dict(Running=True,Paused=False,Restarting=False,Dead=False),
            HostConfig=dict(NetworkMode='none',Privileged=False,ReadonlyRootfs=True,CapDrop=['ALL'],
                CapAdd=[],SecurityOpt=['no-new-privileges'],Memory=1024**3,NanoCpus=10**9,PidsLimit=256,PortBindings={}),
            NetworkSettings=dict(Networks={'none':dict(IPAddress='',GlobalIPv6Address='')},Ports={}),
            Mounts=[dict(Type='bind',Source=str(self.candidate/service),Destination=target,RW=True),
                    dict(Type='bind',Source=str(self.inputs/(service+'.conf')),Destination=config,RW=False)])

    def validate(self, value, service='redis'):
        stores.validate_clone(value,CID,service,IMAGE,IMAGE_ID,self.candidate,self.inputs)

    def test_exact_isolated_store_commands_and_original_rabbit_node(self):
        for service in ('redis','rabbitmq'):
            self.validate(self.record(service),service)
            command=stores.clone_command(service,IMAGE,self.candidate,self.inputs,'autosoft-store-0123456789ab-'+service)
            for fixed in ('--pull=never','--network=none','--read-only','--user=999:999','--cap-drop=ALL','--log-driver=none'):
                self.assertIn(fixed,command)
            self.assertNotIn('--publish',' '.join(command))
            self.assertNotIn('/var/run/docker.sock',' '.join(command))
            if service=='rabbitmq':
                self.assertIn('--hostname=rabbitmq',command)
                self.assertIn('RABBITMQ_NODENAME=rabbit@rabbitmq',command)
                self.assertEqual(command[-1],'rabbitmq-server')
        self.assertIn('aof-load-truncated no',stores.REDIS_CONFIG)
        self.assertNotIn('load_definitions',stores.RABBIT_CONFIG)

    def test_wrong_image_identity_privilege_mount_command_or_network_denied(self):
        changes=[lambda v:v.update(Id='d'*64),lambda v:v.update(Image='sha256:'+'d'*64),
                 lambda v:v.update(Name='/autosoft-redis-1'),lambda v:v['Config'].update(Image='redis:latest'),
                 lambda v:v['Config'].update(User='0:0'),lambda v:v['Config'].update(Cmd=['sh','-c','id']),
                 lambda v:v['State'].update(Running=False),lambda v:v['HostConfig'].update(NetworkMode='bridge'),
                 lambda v:v['HostConfig'].update(Privileged=True),lambda v:v['HostConfig'].update(ReadonlyRootfs=False),
                 lambda v:v['HostConfig'].update(CapAdd=['SYS_ADMIN']),lambda v:v['HostConfig'].update(SecurityOpt=[]),
                 lambda v:v['HostConfig'].update(Memory=0),lambda v:v['HostConfig'].update(PidsLimit=0),
                 lambda v:v['HostConfig'].update(PortBindings={'6379/tcp':[{'HostPort':'6379'}]}),
                 lambda v:v['NetworkSettings'].update(Networks={'bridge':dict(IPAddress='172.17.0.2')}),
                 lambda v:v['Mounts'][0].update(Source=str(self.root/'production/redis')),
                 lambda v:v['Mounts'][1].update(RW=True),
                 lambda v:v['Mounts'].append(dict(Type='bind',Source='/etc',Destination='/host'))]
        for change in changes:
            value=self.record('redis');change(value)
            with self.subTest(change=change),self.assertRaises(ValueError):self.validate(value)
        for field in ('Hostname','Env'):
            value=self.record('rabbitmq');value['Config'][field]='wrong' if field=='Hostname' else []
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate(value,'rabbitmq')

    def test_redis_readonly_native_evidence_uses_stdin_credentials_and_no_values(self):
        responses=['# Persistence\nloading:0\naof_enabled:1\naof_last_write_status:ok\n','PONG\n',
                   'user provisioner on #sensitive-hash ~* +@all\nuser default off\n',
                   '# Keyspace\ndb0:keys=7,expires=2,avg_ttl=1000\n']
        with patch.object(stores,'_output',side_effect=responses) as output:
            evidence=stores._redis_evidence(CID,self.candidate,self.inputs)
        self.assertEqual(evidence['keyspace'],[dict(database=0,keys=7,expiringKeys=2)])
        self.assertEqual(evidence['aclUsers'],2)
        self.assertNotIn('sensitive-hash',json.dumps(evidence))
        self.assertIn('unavailable',evidence['contentBaseline'])
        for call in output.call_args_list:
            command=call.args[0]
            self.assertEqual(command[:9],['docker','exec','-i',CID,'redis-cli','-h','127.0.0.1','-p','6379'])
            self.assertNotIn('--host',command);self.assertNotIn('--port',command)
            self.assertNotIn('synthetic-protected-password',' '.join(command))
            self.assertEqual(call.kwargs['stdin'],b'synthetic-protected-password\n')
            self.assertNotIn('GET',command);self.assertNotIn('FLUSHALL',command)

    def test_redis_corruption_or_loading_cannot_pass(self):
        for info in ('loading:1\n','loading:0\naof_enabled:0\naof_last_write_status:ok\n',
                     'loading:0\naof_enabled:1\naof_last_write_status:err\n',''):
            with self.subTest(info=info),patch.object(stores,'_output',return_value=info),self.assertRaises(ValueError):
                stores._redis_evidence(CID,self.candidate,self.inputs)

    def test_rabbit_counts_without_consuming_or_logging_message_content(self):
        self.assertIn('management.tcp.ip = 127.0.0.1',stores.RABBIT_CONFIG)
        self.assertIn('management.tcp.port = 15672',stores.RABBIT_CONFIG)
        self.assertNotIn('management.tcp.port = none',stores.RABBIT_CONFIG)
        responses=[json.dumps([{'name':'platform'},{'name':'app_docs'}]),
                   json.dumps([dict(name='documents',durable=True,messages_ready=3,messages_unacknowledged=0)]),
                   json.dumps([dict(name='jobs',durable=True,messages_ready=2,messages_unacknowledged=0)])]
        with patch.object(stores,'_output',side_effect=responses) as output:
            evidence=stores._rabbit_evidence(CID,self.inputs)
        self.assertEqual((evidence['vhosts'],evidence['queues'],evidence['readyMessages']),(2,2,5))
        self.assertNotIn('documents',json.dumps(evidence))
        self.assertEqual(evidence['messageContent'],'not consumed or compared')
        for call in output.call_args_list:
            self.assertIn(call.args[0][6],('list_vhosts','list_queues'))
            self.assertNotIn('purge_queue',call.args[0])

    def test_rabbit_active_consumer_or_malformed_queue_metadata_denied(self):
        for row in (dict(name='jobs',durable=True,messages_ready=1,messages_unacknowledged=1),
                    dict(name='jobs',durable=True,messages_ready=-1,messages_unacknowledged=0),
                    dict(name='jobs',durable=True,messages_ready=True,messages_unacknowledged=0)):
            with self.subTest(row=row),patch.object(stores,'_output',side_effect=[json.dumps([{'name':'platform'}]),json.dumps([row])]),self.assertRaises(ValueError):
                stores._rabbit_evidence(CID,self.inputs)

    def test_uncertain_launch_preserves_copy_and_scratch_without_name_cleanup(self):
        for outcome in ('', 'not-a-container-id', RuntimeError('Docker response lost')):
            calls=[]
            def output(args,**kwargs):
                calls.append(args)
                if args[1:3]==['image','inspect']:return IMAGE_ID
                if args[1]=='run':
                    if isinstance(outcome,Exception):raise outcome
                    return outcome
                raise AssertionError('Unknown launch must never delete by name or attempt a guessed ID')
            with self.subTest(outcome=outcome),patch.object(stores.os,'geteuid',return_value=0,create=True),patch.object(stores,'_output',side_effect=output),patch.object(stores.subprocess,'run') as run:
                with self.assertRaises(stores.ColdStoreCleanupUncertain) as caught:
                    stores.check_cold_services(self.candidate,dict(redis=IMAGE),dict(redis=IMAGE))
                self.assertIsNone(caught.exception.container_id)
                self.assertRegex(caught.exception.container_name,r'^autosoft-store-[a-f0-9]{12}-redis$')
                self.assertTrue(Path(caught.exception.inputs).is_dir())
                self.assertTrue((self.candidate/'secrets/runtime/redis-admin').is_file())
                run.assert_not_called()


if __name__=='__main__':unittest.main()

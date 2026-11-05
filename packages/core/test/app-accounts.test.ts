import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { AppAccountBrokerClient } from '../src/app-accounts.ts';

test('account broker rejects external HTTP/credential/path/query authorities before credential dispatch',()=>{
 for(const url of ['http://broker.example.test','https://user:password@broker.example.test','https://broker.example.test/path','https://broker.example.test/?credential=test','https://broker.example.test/#fragment'])assert.throws(()=>new AppAccountBrokerClient({url,token:'synthetic-secret',approvalKey:Buffer.alloc(32)}));
});
test('malformed account broker configuration exposes only a fixed error without Node URL input properties',()=>{
 let calls=0;
 assert.throws(()=>new AppAccountBrokerClient({url:'https://[invalid-synthetic-secret',token:'synthetic-secret',approvalKey:Buffer.alloc(32),fetch:async()=>{calls++;return new Response('{}')}}),error=>error instanceof Error&&error.message==='An exact trusted HTTPS account broker authority is required.'&&!Object.hasOwn(error,'input')&&!Object.hasOwn(error,'cause')&&!JSON.stringify(error).includes('synthetic-secret'));
 assert.equal(calls,0);
});
test('exact signed account payload uses only fixed HTTPS authority and forbids redirects',async()=>{
 const key=Buffer.alloc(32,5),input={operationId:'synthetic-operation'};let calls=0;
 const client=new AppAccountBrokerClient({url:'https://broker.example.test',token:'synthetic-secret',approvalKey:key,fetch:async(url,options)=>{calls++;assert.equal(String(url),'https://broker.example.test/v1/accounts/disable');assert.equal(options?.redirect,'error');assert.equal((options?.headers as Record<string,string>)['x-autosoft-proof'],createHmac('sha256',key).update(JSON.stringify(input)).digest('hex'));return new Response(JSON.stringify({status:'pending'}),{status:200})}});
 assert.equal((await client.disable(input as never)).status,'pending');assert.equal(calls,1);
});
test('account transport failures/oversized responses expose no provider body, URL or secret and never imply rejection',async()=>{
 for(const mode of ['exception','oversized','redirect']){const client=new AppAccountBrokerClient({url:'https://broker.example.test',token:'synthetic-secret',approvalKey:Buffer.alloc(32),fetch:async()=>{if(mode==='exception')throw new Error('synthetic-secret private endpoint');if(mode==='oversized')return new Response('synthetic-secret'.repeat(10000));const response=new Response('{}');Object.defineProperty(response,'redirected',{value:true});return response}});
 await assert.rejects(client.snapshot({}as never),error=>error instanceof Error&&!/synthetic-secret|private endpoint|https:/.test(error.message)&&!(error as{confirmedRejected?:boolean}).confirmedRejected)}
});
test('account receipts require exact HTTP200, fatal UTF8 and a bounded matching declared length',async()=>{
 const cases = [
  {status:202,bytes:Buffer.from('{"rejectedBeforeExecution":true}')},
  {status:200,bytes:Buffer.from([0x7b,0x22,0x61,0x22,0x3a,0x22,0xff,0x22,0x7d])},
  ...['-1','01','1.0','65537','9007199254740993','1','100'].map(length=>({status:200,bytes:Buffer.from('{}'),length})),
  {status:409,bytes:Buffer.from('{"rejectedBeforeExecution":true}'),length:'1'},
 ];
 for(const item of cases){let cancelled=false;const client=new AppAccountBrokerClient({url:'https://broker.example.test',token:'synthetic-secret',approvalKey:Buffer.alloc(32),fetch:async()=>new Response(new ReadableStream({start(controller){controller.enqueue(item.bytes);controller.close()},cancel(){cancelled=true}}),{status:item.status,headers:'length'in item?{'content-length':item.length!}:{}})});await assert.rejects(client.snapshot({}as never),error=>error instanceof Error&&(error as{confirmedRejected?:boolean}).confirmedRejected===false);if(item.status===202||'length'in item&&['-1','01','1.0','65537','9007199254740993'].includes(item.length!))assert.equal(cancelled,true);}
 const client=new AppAccountBrokerClient({url:'https://broker.example.test',token:'synthetic-secret',approvalKey:Buffer.alloc(32),fetch:async()=>new Response('{}',{headers:{'content-length':'2'}})});assert.deepEqual(await client.snapshot({}as never),{});
});
test('only a valid negative broker receipt can confirm rejection before execution',async()=>{
 for(const value of [true,false,'true',1]){const client=new AppAccountBrokerClient({url:'https://broker.example.test',token:'synthetic-secret',approvalKey:Buffer.alloc(32),fetch:async()=>new Response(JSON.stringify({rejectedBeforeExecution:value}),{status:409})});await assert.rejects(client.disable({}as never),error=>(error as{confirmedRejected?:boolean}).confirmedRejected===(value===true));}
 const client=new AppAccountBrokerClient({url:'https://broker.example.test',token:'synthetic-secret',approvalKey:Buffer.alloc(32),fetch:async()=>{throw Object.assign(new Error('private'),{confirmedRejected:true})}});await assert.rejects(client.disable({}as never),error=>(error as{confirmedRejected?:boolean}).confirmedRejected===false);
});

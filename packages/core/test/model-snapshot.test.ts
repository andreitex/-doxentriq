import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ModelGateway, type BudgetHooks, type CompletionRequest, type ModelCatalog, type ModelGatewayConfig } from '../src/models.js';

const now=new Date('2026-10-12T15:00:00Z');
const input={stage:'review' as const,jobId:'synthetic-snapshot-job',system:'s',prompt:'p',maxOutputTokens:10};
const definition={id:'qualified-model',provider:'openai' as const,tier:'strong' as const,inputUsdPerMillion:1,outputUsdPerMillion:1,
  cachedInputUsdPerMillion:1,cacheWriteUsdPerMillion:1,effort:'high',qualified:true,maxInputTokens:90000,maxOutputTokens:100};
const receipt=(tokens=10)=>({service_tier:'default',usage:{input_tokens:tokens,output_tokens:1},output:[{type:'message',content:[{type:'output_text',text:'synthetic completion'}]}]});

function fixture(provider:'openai'|'anthropic'='openai'){
  const catalog:ModelCatalog={schemaVersion:1,pricesVerifiedAt:now.toISOString(),sources:['https://developers.openai.com/api/docs/guides/model-selection'],models:[{...definition,provider}]};
  const keys={openai:'synthetic-original-openai',anthropic:'synthetic-original-anthropic'};
  const secrets=['synthetic-original-secret'];
  const sent:{url:string;body:any;headers:Headers}[]=[];
  const config:ModelGatewayConfig={catalog,apiKeys:keys,redactionSecrets:secrets,now:()=>now,fetch:async(url,init)=>{
    sent.push({url:String(url),body:JSON.parse(String(init?.body)),headers:new Headers(init?.headers)});
    return Response.json(provider==='openai'?receipt():{usage:{service_tier:'standard',input_tokens:10,output_tokens:1},content:[{type:'text',text:'synthetic completion'}]});
  }};
  const gateway=new ModelGateway(config);const reserved:number[]=[];const settled:number[]=[];
  const hooks:BudgetHooks={reserve:async amount=>{reserved.push(amount);return `r-${reserved.length}`;},settle:async(_id,amount)=>{settled.push(amount);}};
  return {gateway,config,catalog,keys,secrets,sent,reserved,settled,hooks};
}

test('configuration snapshots keep the qualified model and credentials despite caller mutation',async()=>{
  const f=fixture();f.catalog.models[0]!.qualified=false;f.catalog.models[0]!.id='different-model';f.catalog.models.splice(0);
  f.catalog.pricesVerifiedAt='2000-01-01T00:00:00Z';f.keys.openai='replacement-key';f.secrets.splice(0);
  const result=await f.gateway.complete({...input,prompt:'p synthetic-original-secret'},f.hooks);
  assert.equal(result.model,'qualified-model');assert.equal(f.sent.length,1);
  assert.equal(f.sent[0]!.headers.get('authorization'),'Bearer synthetic-original-openai');
  assert.ok(!f.sent[0]!.body.input.includes('synthetic-original-secret'));
});

test('awaiting reservation cannot change a call to an unqualified differently priced provider',async()=>{
  const f=fixture();const original=f.catalog.models[0]!;
  const result=await f.gateway.complete(input,{...f.hooks,reserve:async amount=>{
    f.reserved.push(amount);Object.assign(original,{id:'unqualified-premium',provider:'anthropic',qualified:false,inputUsdPerMillion:1000,outputUsdPerMillion:1000,effort:'max'});
    f.keys.openai='replacement-key';return 'r-1';
  }});
  assert.equal(f.sent.length,1);assert.equal(f.sent[0]!.url,'https://api.openai.com/v1/responses');
  assert.equal(f.sent[0]!.body.model,'qualified-model');assert.equal(f.sent[0]!.body.reasoning.effort,'high');
  assert.equal(result.provider,'openai');assert.equal(result.model,'qualified-model');assert.equal(result.costUsd,11/1e6);
  assert.equal(f.settled[0],result.costUsd);assert.ok(result.costUsd<=f.reserved[0]!);
});

test('public candidates cannot mutate retained qualification or reservation prices',async()=>{
  const f=fixture();const candidate=f.gateway.candidates('review')[0]!;
  assert.ok(Object.isFrozen(candidate));assert.equal(Reflect.set(candidate,'qualified',false),false);
  assert.equal(Reflect.set(candidate,'inputUsdPerMillion',1000),false);
  const view=f.gateway.candidates('review');view.splice(0);
  assert.equal((await f.gateway.complete(input,f.hooks)).model,'qualified-model');assert.equal(f.sent.length,1);
});

test('both provider payloads use the schema captured before reservation mutation',async()=>{
  for(const provider of ['openai','anthropic'] as const){
    const f=fixture(provider);const schema={type:'object',properties:{name:{type:'string'}},required:['name'],additionalProperties:false};
    const expected=JSON.parse(JSON.stringify(schema));
    await f.gateway.complete({...input,schema},{...f.hooks,reserve:async amount=>{
      f.reserved.push(amount);schema.properties.name.type='x'.repeat(100000);schema.required.push('changed');return 'r-1';
    }});
    const actual=provider==='openai'?f.sent[0]!.body.text.format.schema:f.sent[0]!.body.output_config.format.schema;
    assert.deepEqual(actual,expected);assert.equal(f.sent.length,1);
    assert.equal(f.reserved[0],(Buffer.byteLength('sp'+JSON.stringify(expected),'utf8')+2048+10)/1e6);
  }
});

test('stateful schema serialization is called once so estimated and sent schema stay equal',async()=>{
  const f=fixture();let serializations=0;const expected={type:'object',additionalProperties:false};
  const schema={toJSON:()=>{serializations++;return serializations===1?expected:{description:'x'.repeat(100000)};}};
  await f.gateway.complete({...input,schema},f.hooks);
  assert.equal(serializations,1);assert.deepEqual(f.sent[0]!.body.text.format.schema,expected);
  assert.equal(f.reserved[0],(Buffer.byteLength('sp'+JSON.stringify(expected),'utf8')+2048+10)/1e6);
});

test('unserializable schema cannot reserve or dispatch a paid call',async()=>{
  for(const schema of [{toJSON:()=>undefined},{toJSON:()=>{throw new Error('synthetic serialization failure');}}]){
    const f=fixture();await assert.rejects(f.gateway.complete({...input,schema},f.hooks),/serialized|serialization failure/);
    assert.deepEqual(f.reserved,[]);assert.deepEqual(f.sent,[]);assert.deepEqual(f.settled,[]);
  }
});

test('confirmed-refusal fallback keeps the original schema presence and output limit',async()=>{
  const f=fixture();const expected={type:'object',additionalProperties:false};
  const request:CompletionRequest={...input,schema:{toJSON:()=>{request.schema=undefined;return expected;}}};
  f.catalog.models.push({...definition,id:'qualified-fallback',inputUsdPerMillion:2});
  const gateway=new ModelGateway({...f.config,fetch:async(url,init)=>{
    f.sent.push({url:String(url),body:JSON.parse(String(init?.body)),headers:new Headers(init?.headers)});
    if(f.sent.length===1){request.maxOutputTokens=100;return new Response(null,{status:429});}
    return Response.json(receipt());
  }});
  assert.equal((await gateway.complete(request,f.hooks)).model,'qualified-fallback');
  assert.equal(f.sent.length,2);assert.deepEqual(f.sent.map(value=>value.body.max_output_tokens),[10,10]);
  for(const value of f.sent)assert.deepEqual(value.body.text.format.schema,expected);
  assert.equal(f.settled[0],0);assert.equal(f.reserved.length,2);
});

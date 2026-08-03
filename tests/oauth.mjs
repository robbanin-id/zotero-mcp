import worker from '../src/worker.js';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
const dbPath = '/tmp/zotero-mcp-test.sqlite';
try { rmSync(dbPath); } catch {}
execFileSync('sqlite3', [dbPath], { input: readFileSync('schema.sql'), stdio: ['pipe','ignore','inherit'] });
function sqlQuote(v){ if(v===null||v===undefined)return 'NULL'; if(typeof v==='number')return String(v); if(typeof v==='boolean')return v?'1':'0'; return "'"+String(v).replaceAll("'","''")+"'"; }
function run(sql){ return execFileSync('sqlite3',[dbPath,'.mode json',sql],{encoding:'utf8'}).trim(); }
class Stmt { constructor(sql){this.sql=sql;this.args=[];} bind(...args){this.args=args;return this;} compiled(){let i=0;return this.sql.replaceAll('?',()=>sqlQuote(this.args[i++]));} async first(){const s=run(this.compiled());const a=s?JSON.parse(s):[];return a[0]||null;} async all(){const s=run(this.compiled());return {results:s?JSON.parse(s):[]};} async run(){run(this.compiled());return {success:true,meta:{changes:1}};} }
class DB {prepare(sql){return new Stmt(sql);} async batch(stmts){for(const s of stmts)await s.run();return [];} }
const env={BASE_URL:'https://example.test',ENCRYPTION_KEY:'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',ZOTERO_DB:new DB()};
const realFetch=globalThis.fetch;
globalThis.fetch=async (input,init={})=>{
  const u=new URL(input);
  if(u.origin==='https://api.zotero.org'){
    if(u.pathname.startsWith('/keys/')) return new Response(JSON.stringify({userID:12345,access:{user:{library:true,write:true,files:true,notes:true}}}),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/users/12345') return new Response(JSON.stringify({userID:12345,name:'Test Library'}),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/users/12345/items') return new Response(JSON.stringify([{key:'AAAA1111',version:1,data:{itemType:'journalArticle',title:'Test Paper',DOI:'10.1234/test'}}]),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/users/12345/items/AAAA1111') return new Response(JSON.stringify({key:'AAAA1111',version:1,data:{itemType:'journalArticle',title:'Test Paper',DOI:'10.1234/test',relations:{}}}),{status:200,headers:{'content-type':'application/json'}});
    return new Response(JSON.stringify([]),{status:200,headers:{'content-type':'application/json'}});
  }
  return realFetch(input,init);
};
const req=(url,opts={})=>worker.fetch(new Request(url,opts),env);
const reg=await req('https://example.test/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'Test',redirect_uris:['https://client.test/cb']})});
if(reg.status!==201)throw new Error('register '+reg.status+' '+await reg.text());
const client=await reg.json();
const verifier='test-verifier-123456789';
const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))); let b='';for(const x of digest)b+=String.fromCharCode(x);const challenge=btoa(b).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
const au=await req('https://example.test/authorize?client_id='+client.client_id+'&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&state=s1&code_challenge='+challenge+'&code_challenge_method=S256');
const page=await au.text();const flow=page.match(/name="flow_id" value="([^"]+)"/)?.[1];if(!flow)throw new Error('flow missing');
const form=new URLSearchParams({flow_id:flow,api_key:'ABCDEFGHIJKLMNOPQRSTUVWX1234',library_type:'user',library_id:'12345'});
const ar=await req('https://example.test/authorize',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form.toString()});
if(ar.status!==302)throw new Error('authorize '+ar.status+' '+await ar.text());
const loc=ar.headers.get('location');const code=new URL(loc).searchParams.get('code');if(!code)throw new Error('code missing');
const tr=await req('https://example.test/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier}).toString()});
if(tr.status!==200)throw new Error('token '+tr.status+' '+await tr.text());const tokens=await tr.json();
const list=await req('https://example.test/mcp',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+tokens.access_token},body:JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})});
const catalog=await list.json();
const call=await req('https://example.test/mcp',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+tokens.access_token},body:JSON.stringify({jsonrpc:'2.0',id:2,method:'tools/call',params:{name:'zotero_search',arguments:{action:'search_items',query:'Test',limit:5}}})});
console.log(JSON.stringify({register:reg.status,authorize:ar.status,token:tr.status,tools:list.status,toolCount:catalog.result.tools.length,call:call.status,callPayload:(await call.json()).result?.structuredContent},null,2));

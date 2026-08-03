import worker from '../worker.js';
import { execFileSync } from 'node:child_process';
import { readFileSync, rmSync } from 'node:fs';
const dbPath = '/tmp/zotero-mcp-all-libraries.sqlite';
try { rmSync(dbPath); } catch {}
execFileSync('sqlite3', [dbPath], { input: readFileSync('schema.sql'), stdio: ['pipe','ignore','inherit'] });
function sqlQuote(v){ if(v===null||v===undefined)return 'NULL'; if(typeof v==='number')return String(v); if(typeof v==='boolean')return v?'1':'0'; return "'"+String(v).replaceAll("'","''")+"'"; }
function run(sql){ return execFileSync('sqlite3',[dbPath,'.mode json',sql],{encoding:'utf8'}).trim(); }
class Stmt { constructor(sql){this.sql=sql;this.args=[];} bind(...args){this.args=args;return this;} compiled(){let i=0;return this.sql.replaceAll('?',()=>sqlQuote(this.args[i++]));} async first(){const s=run(this.compiled());const a=s?JSON.parse(s):[];return a[0]||null;} async all(){const s=run(this.compiled());return {results:s?JSON.parse(s):[]};} async run(){run(this.compiled());return {success:true,meta:{changes:1}};} }
class DB {prepare(sql){return new Stmt(sql);} async batch(stmts){for(const s of stmts)await s.run();return [];} }
const env={BASE_URL:'https://example.test',ENCRYPTION_KEY:'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',ZOTERO_DB:new DB()};
const realFetch=globalThis.fetch;
globalThis.fetch=async (input,init={})=>{
  const u=new URL(input); const method=init.method||'GET';
  if(u.origin==='https://api.zotero.org'){
    if(u.pathname.startsWith('/keys/')) return new Response(JSON.stringify({userID:12345,access:{user:{library:true,write:true,files:true,notes:true},groups:{all:{library:true,write:true}}}}),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/users/12345') return new Response(JSON.stringify({userID:12345,name:'Personal'}),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/users/12345/groups') return new Response(JSON.stringify([{id:98765,name:'Research Group'}]),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/users/12345/items' && method==='GET') return new Response(JSON.stringify([{key:'USERITEM1',data:{itemType:'journalArticle',title:'Personal Result'}}]),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/groups/98765/items' && method==='GET') return new Response(JSON.stringify([{key:'GROUPITEM1',data:{itemType:'journalArticle',title:'Group Result'}}]),{status:200,headers:{'content-type':'application/json'}});
    if(u.pathname==='/groups/98765/collections' && method==='POST') return new Response(JSON.stringify([{key:'COLL1',data:{name:'Created'}}]),{status:200,headers:{'content-type':'application/json'}});
    return new Response(JSON.stringify([]),{status:200,headers:{'content-type':'application/json'}});
  }
  return realFetch(input,init);
};
const req=(url,opts={})=>worker.fetch(new Request(url,opts),env);
const reg=await req('https://example.test/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_name:'All libraries test',redirect_uris:['https://client.test/cb']})});
const client=await reg.json(); const verifier='all-libraries-verifier-123456789';
const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))); let b='';for(const x of digest)b+=String.fromCharCode(x);const challenge=btoa(b).replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
const au=await req('https://example.test/authorize?client_id='+client.client_id+'&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&code_challenge='+challenge+'&code_challenge_method=S256');
const flow=(await au.text()).match(/name="flow_id" value="([^"]+)"/)?.[1];
const ar=await req('https://example.test/authorize',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({flow_id:flow,api_key:'ABCDEFGHIJKLMNOPQRSTUVWX1234',library_type:'all',library_id:''}).toString()});
if(ar.status!==302) throw new Error('authorize '+ar.status+' '+await ar.text());
const code=new URL(ar.headers.get('location')).searchParams.get('code');
const tr=await req('https://example.test/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:client.client_id,code,code_verifier:verifier}).toString()});
const tokens=await tr.json(); const auth={authorization:'Bearer '+tokens.access_token,'content-type':'application/json'};
const call=async (id,params)=>{const r=await req('https://example.test/mcp',{method:'POST',headers:auth,body:JSON.stringify({jsonrpc:'2.0',id,method:'tools/call',params:{name:params.name,arguments:params.arguments}})});const j=await r.json();if(r.status!==200||j.result?.isError)throw new Error(JSON.stringify(j));return j.result.structuredContent;};
const libs=await call(1,{name:'zotero_retrieval',arguments:{action:'list_libraries'}}); const search=await call(2,{name:'zotero_search',arguments:{action:'search_items',query:'Result'}}); const groupWrite=await call(3,{name:'zotero_write',arguments:{action:'create_collection',library_type:'group',library_id:'98765',name:'Created'}});
if(libs.libraries?.length!==2) throw new Error('library discovery failed '+JSON.stringify(libs));
if(search.items?.length!==2 || !search.items.some(x=>x.mcp_library?.type==='group')) throw new Error('fanout failed '+JSON.stringify(search));
if(!groupWrite.data && !groupWrite.items) throw new Error('target group write failed '+JSON.stringify(groupWrite));
console.log(JSON.stringify({authorize:ar.status,token:tr.status,libraries:libs.libraries,searchCount:search.count,searchLibraries:search.libraries,groupWriteOk:true},null,2));

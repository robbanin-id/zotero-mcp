// Zotero MCP for Cloudflare Workers
// Cloudflare-native multi-user OAuth 2.1 adapter around the Zotero Web API.
// The 54yyyu tool surface is represented by categorized umbrella tools so
// every user gets isolated credentials and clients receive a small catalog.

const VERSION = '0.1.0';
const SERVER_NAME = 'zotero-mcp';
const MCP_PROTOCOL = '2025-03-26';
const ACCESS_TTL = 3600;
const REFRESH_TTL = 30 * 24 * 3600;
const CODE_TTL = 10 * 60;
const FLOW_TTL = 15 * 60;
const ZOTERO_BASE = 'https://api.zotero.org';
const SCITE_BASE = 'https://api.scite.ai';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization,MCP-Protocol-Version,Accept',
  'Access-Control-Expose-Headers': 'WWW-Authenticate,MCP-Protocol-Version',
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...CORS, ...headers },
  });
}
function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', ...CORS, ...headers },
  });
}
function redirect(url, status = 302) { return Response.redirect(url, status); }
function now() { return Date.now(); }
function text(v, fallback = '') { return v == null ? fallback : String(v); }
function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}
function trimSlash(v) { return String(v || '').replace(/\/+$/, ''); }
function baseUrl(request, env) { return trimSlash(env.BASE_URL || new URL(request.url).origin); }
function quoteHtml(v) {
  return text(v).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[c]);
}
function randomHex(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map(x => x.toString(16).padStart(2, '0')).join('');
}
function bytesToB64Url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function hexBytes(hex) {
  const clean = String(hex || '').replace(/[^0-9a-f]/gi, '');
  if (!clean || clean.length % 2) throw new Error('Invalid hex data');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function hexToBytes(hex) {
  const out = hexBytes(hex);
  if (out.length !== 32) throw new Error('ENCRYPTION_KEY must be 32-byte hex');
  return out;
}
async function sha256Bytes(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value))));
}
async function sha256(value) {
  return [...await sha256Bytes(value)].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function pkceS256(verifier) { return bytesToB64Url(await sha256Bytes(verifier || '')); }

function requireDb(env) {
  if (!env.ZOTERO_DB) throw new Error('ZOTERO_DB binding is not configured');
  return env.ZOTERO_DB;
}
async function dbFirst(env, sql, ...args) {
  return requireDb(env).prepare(sql).bind(...args).first();
}
async function dbAll(env, sql, ...args) {
  const r = await requireDb(env).prepare(sql).bind(...args).all();
  return r.results || [];
}
async function dbRun(env, sql, ...args) {
  return requireDb(env).prepare(sql).bind(...args).run();
}
async function dbBatch(env, statements) {
  return requireDb(env).batch(statements);
}

async function encrypt(plain, env) {
  const key = await crypto.subtle.importKey('raw', hexToBytes(env.ENCRYPTION_KEY), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain));
  return bytesToHex(iv) + ':' + bytesToHex(new Uint8Array(ciphertext));
}
async function decrypt(encoded, env) {
  const [ivHex, dataHex] = String(encoded || '').split(':');
  const key = await crypto.subtle.importKey('raw', hexToBytes(env.ENCRYPTION_KEY), 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexBytes(ivHex).slice(0, 12) }, key, hexBytes(dataHex));
  return new TextDecoder().decode(plain);
}
function bytesToHex(bytes) { return [...bytes].map(x => x.toString(16).padStart(2, '0')).join(''); }

function oauthMetadata(base) {
  return {
    issuer: base,
    authorization_endpoint: base + '/authorize',
    token_endpoint: base + '/token',
    registration_endpoint: base + '/register',
    revocation_endpoint: base + '/revoke',
    scopes_supported: ['mcp'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
  };
}
function resourceMetadata(base) {
  return {
    resource: base + '/mcp',
    authorization_servers: [base],
    scopes_supported: ['mcp'],
    bearer_methods_supported: ['header'],
  };
}

async function zoteroFetch(key, method, path, { query, body, headers = {}, raw = false } = {}) {
  const u = new URL(ZOTERO_BASE + path);
  if (query) for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') u.searchParams.set(k, String(v));
  }
  const response = await fetch(u, {
    method,
    headers: {
      Authorization: 'Bearer ' + key,
      'Zotero-API-Version': '3',
      'User-Agent': 'Robbanin-Zotero-MCP/' + VERSION,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...headers,
    },
    body: body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const contentType = response.headers.get('content-type') || '';
  const value = raw || !contentType.includes('json') ? await response.text() : await response.json();
  if (!response.ok) {
    const detail = typeof value === 'string' ? value.slice(0, 500) : JSON.stringify(value).slice(0, 500);
    const error = new Error('Zotero API ' + response.status + (detail ? ': ' + detail : ''));
    error.status = response.status;
    error.upstream = value;
    throw error;
  }
  return {
    data: value,
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
  };
}
function librarySegment(grant) { return grant.library_type === 'group' ? 'groups' : 'users'; }
function libraryRoot(grant) { return '/' + librarySegment(grant) + '/' + encodeURIComponent(grant.library_id); }
function itemPath(grant, key, suffix = '') { return libraryRoot(grant) + '/items/' + encodeURIComponent(String(key).toUpperCase()) + suffix; }
function collectionPath(grant, key, suffix = '') { return libraryRoot(grant) + '/collections/' + encodeURIComponent(String(key).toUpperCase()) + suffix; }
function zoteroWriteHeaders(version) {
  const h = { 'Zotero-Write-Token': randomHex(16) };
  if (version !== undefined && version !== null && version !== '') h['If-Unmodified-Since-Version'] = String(version);
  return h;
}
function apiResult(result) {
  return { data: result.data, status: result.status, headers: { lastModifiedVersion: result.headers['last-modified-version'] || null, etag: result.headers.etag || null } };
}

async function validateZoteroCredential(apiKey, libraryType, libraryId) {
  if (!/^[A-Za-z0-9]{20,80}$/.test(apiKey)) throw new Error('Zotero API key format is invalid');
  if (!['user', 'group'].includes(libraryType)) throw new Error('library_type must be user or group');
  if (!/^[0-9]+$/.test(String(libraryId))) throw new Error('library_id must be numeric');
  const keyInfo = await zoteroFetch(apiKey, 'GET', '/keys/' + encodeURIComponent(apiKey));
  const access = keyInfo.data?.access || {};
  const scope = libraryType === 'group' ? access.group : access.user;
  if (!scope?.library) throw new Error('This Zotero API key does not have library read access');
  if (!scope?.write) throw new Error('This Zotero API key must have write access for this MCP');
  const userId = keyInfo.data?.userID || keyInfo.data?.userId || null;
  const root = '/' + (libraryType === 'group' ? 'groups' : 'users') + '/' + encodeURIComponent(String(libraryId));
  const library = await zoteroFetch(apiKey, 'GET', root, { query: { limit: 1 } });
  return {
    userId,
    access: { library: !!scope.library, write: !!scope.write, files: !!scope.files, notes: !!scope.notes },
    library: library.data,
  };
}

function authorizePage(flow) {
  const flowJson = JSON.stringify(flow).replace(/</g, '\\u003c');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Zotero MCP</title><style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:520px;margin:7vh auto;padding:0 22px;line-height:1.5;color:#222}h1{font-size:1.45rem;margin:.2rem 0}.sub{color:#666;font-size:.92rem;margin-bottom:1.4rem}label{display:block;font-weight:600;margin:1rem 0 .35rem}input,select{width:100%;box-sizing:border-box;padding:.68rem;border:1px solid #bbb;border-radius:8px;font-size:1rem}button{width:100%;margin-top:1.25rem;padding:.75rem;border:0;border-radius:8px;background:#3b5ccc;color:white;font-size:1rem;font-weight:600;cursor:pointer}button:disabled{opacity:.5}.hint{font-size:.82rem;color:#777;margin-top:.35rem}.err{color:#b42318;min-height:1.1rem;margin-top:.55rem}.security{background:#f5f7ff;border-radius:9px;padding:.75rem;font-size:.85rem}a{color:#3156c9}</style></head><body>
<h1>Connect your Zotero library</h1><div class="sub">This server stores your Zotero API key encrypted. The AI client receives only an MCP access token, never your Zotero key.</div>
<div class="security">Create or review your key at <a href="https://www.zotero.org/settings/keys" target="_blank" rel="noopener">zotero.org/settings/keys</a>. Enable library access and write access.</div>
<form method="POST" action="/authorize"><input type="hidden" name="flow_id" value="${quoteHtml(flow.flow_id)}">
<label>Zotero API key</label><input name="api_key" type="password" autocomplete="off" required placeholder="Paste your Zotero API key"><div class="hint">The key is validated server-side and not displayed to the AI client.</div>
<label>Library type</label><select name="library_type"><option value="user">My user library</option><option value="group">A group library</option></select>
<label>Library ID</label><input name="library_id" inputmode="numeric" required placeholder="Your Zotero user ID or group ID"><div class="hint">For a user library, use the numeric user ID. For a group library, use the group ID.</div>
<button type="submit">Validate and connect</button><div class="err"></div></form></body></html>`;
}

async function handleOAuth(request, env, url) {
  const base = baseUrl(request, env);
  const path = url.pathname;
  if (path === '/.well-known/oauth-authorization-server') return json(oauthMetadata(base));
  if (path === '/.well-known/oauth-protected-resource') return json(resourceMetadata(base));

  if (path === '/register' && request.method === 'POST') {
    let body = {};
    try { body = await request.json(); } catch {}
    const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter(x => typeof x === 'string') : [];
    if (!redirectUris.length || redirectUris.length > 20 || !redirectUris.every(x => x.startsWith('https://'))) {
      return json({ error: 'invalid_client_metadata', error_description: 'redirect_uris must contain HTTPS URLs' }, 400);
    }
    const clientId = randomHex(16);
    await dbRun(env,
      'INSERT INTO oauth_clients(client_id,client_name,redirect_uris,created_at) VALUES(?,?,?,?)',
      clientId, text(body.client_name, 'MCP Client').slice(0, 120), JSON.stringify(redirectUris), now());
    return json({
      client_id: clientId,
      client_name: text(body.client_name, 'MCP Client').slice(0, 120),
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }, 201);
  }

  if (path === '/authorize' && request.method === 'GET') {
    const clientId = text(url.searchParams.get('client_id'));
    const redirectUri = text(url.searchParams.get('redirect_uri'));
    const state = text(url.searchParams.get('state'));
    const codeChallenge = text(url.searchParams.get('code_challenge'));
    const method = text(url.searchParams.get('code_challenge_method'));
    if (!clientId || !redirectUri || !codeChallenge || method !== 'S256') return html('Invalid OAuth request: PKCE S256 is required.', 400);
    const client = await dbFirst(env, 'SELECT * FROM oauth_clients WHERE client_id=?', clientId);
    if (!client) return html('Unknown OAuth client.', 400);
    let redirects = [];
    try { redirects = JSON.parse(client.redirect_uris); } catch {}
    if (!redirects.includes(redirectUri)) return html('Invalid redirect URI.', 400);
    const flowId = randomHex(20);
    await dbRun(env,
      'INSERT INTO oauth_requests(flow_id,client_id,redirect_uri,state,code_challenge,created_at,expires_at) VALUES(?,?,?,?,?,?,?)',
      flowId, clientId, redirectUri, state, codeChallenge, now(), now() + FLOW_TTL * 1000);
    return html(authorizePage({ flow_id: flowId }));
  }

  if (path === '/authorize' && request.method === 'POST') {
    const form = await request.formData();
    const flowId = text(form.get('flow_id'));
    const flow = await dbFirst(env, 'SELECT * FROM oauth_requests WHERE flow_id=? AND expires_at>?', flowId, now());
    if (!flow) return html('This authorization request expired. Close the window and reconnect from your MCP client.', 400);
    const apiKey = text(form.get('api_key')).trim();
    const libraryType = text(form.get('library_type')).trim();
    const libraryId = text(form.get('library_id')).trim();
    let validated;
    try {
      validated = await validateZoteroCredential(apiKey, libraryType, libraryId);
    } catch (e) {
      return html(`<p>Could not validate this Zotero connection.</p><p>${quoteHtml(e.message)}</p><p><a href="javascript:history.back()">Go back</a></p>`, 400);
    }
    const grantId = randomHex(16);
    const enc = await encrypt(apiKey, env);
    const accessJson = JSON.stringify(validated.access);
    await dbRun(env,
      'INSERT INTO grants(grant_id,zotero_key_enc,library_type,library_id,zotero_user_id,key_access_json,created_at) VALUES(?,?,?,?,?,?,?)',
      grantId, enc, libraryType, libraryId, validated.userId, accessJson, now());
    const code = randomHex(32);
    await dbRun(env,
      'INSERT INTO oauth_codes(code_hash,client_id,grant_id,code_challenge,created_at,expires_at) VALUES(?,?,?,?,?,?)',
      await sha256(code), flow.client_id, grantId, flow.code_challenge, now(), now() + CODE_TTL * 1000);
    await dbRun(env, 'DELETE FROM oauth_requests WHERE flow_id=?', flowId);
    const callback = new URL(flow.redirect_uri);
    callback.searchParams.set('code', code);
    if (flow.state) callback.searchParams.set('state', flow.state);
    return redirect(callback.toString());
  }

  if (path === '/token' && request.method === 'POST') {
    const form = await request.formData();
    const grantType = text(form.get('grant_type'));
    if (grantType === 'authorization_code') {
      const code = text(form.get('code'));
      const verifier = text(form.get('code_verifier'));
      const row = await dbFirst(env, 'SELECT * FROM oauth_codes WHERE code_hash=? AND expires_at>?', await sha256(code), now());
      if (!row) return json({ error: 'invalid_grant', error_description: 'Code not found or expired' }, 400);
      if (await pkceS256(verifier) !== row.code_challenge) return json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
      await dbRun(env, 'DELETE FROM oauth_codes WHERE code_hash=?', row.code_hash);
      const accessToken = randomHex(32);
      const refreshToken = randomHex(32);
      const t = now();
      await dbBatch(env, [
        requireDb(env).prepare('INSERT INTO oauth_tokens(token_hash,grant_id,token_type,created_at,expires_at) VALUES(?,?,?,?,?)').bind(await sha256(accessToken), row.grant_id, 'access', t, t + ACCESS_TTL * 1000),
        requireDb(env).prepare('INSERT INTO oauth_tokens(token_hash,grant_id,token_type,created_at,expires_at) VALUES(?,?,?,?,?)').bind(await sha256(refreshToken), row.grant_id, 'refresh', t, t + REFRESH_TTL * 1000),
      ]);
      return json({ access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token: refreshToken, scope: 'mcp' });
    }
    if (grantType === 'refresh_token') {
      const refresh = text(form.get('refresh_token'));
      const row = await dbFirst(env, 'SELECT * FROM oauth_tokens WHERE token_hash=? AND token_type=? AND expires_at>? AND revoked_at IS NULL', await sha256(refresh), 'refresh', now());
      if (!row) return json({ error: 'invalid_grant' }, 400);
      await dbRun(env, 'UPDATE oauth_tokens SET revoked_at=? WHERE token_hash=?', now(), row.token_hash);
      const accessToken = randomHex(32);
      const refreshToken = randomHex(32);
      const t = now();
      await dbBatch(env, [
        requireDb(env).prepare('INSERT INTO oauth_tokens(token_hash,grant_id,token_type,created_at,expires_at) VALUES(?,?,?,?,?)').bind(await sha256(accessToken), row.grant_id, 'access', t, t + ACCESS_TTL * 1000),
        requireDb(env).prepare('INSERT INTO oauth_tokens(token_hash,grant_id,token_type,created_at,expires_at) VALUES(?,?,?,?,?)').bind(await sha256(refreshToken), row.grant_id, 'refresh', t, t + REFRESH_TTL * 1000),
      ]);
      return json({ access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token: refreshToken, scope: 'mcp' });
    }
    return json({ error: 'unsupported_grant_type' }, 400);
  }

  if (path === '/revoke' && request.method === 'POST') {
    const form = await request.formData();
    const token = text(form.get('token'));
    if (token) await dbRun(env, 'UPDATE oauth_tokens SET revoked_at=? WHERE token_hash=?', now(), await sha256(token));
    return new Response(null, { status: 200, headers: CORS });
  }
  return null;
}

async function authenticate(request, env) {
  const header = request.headers.get('Authorization') || '';
  const token = header.replace(/^Bearer\s+/i, '').trim();
  if (!token) return null;
  const row = await dbFirst(env,
    'SELECT t.grant_id,t.expires_at,g.* FROM oauth_tokens t JOIN grants g ON g.grant_id=t.grant_id WHERE t.token_hash=? AND t.token_type=? AND t.expires_at>? AND t.revoked_at IS NULL AND g.revoked_at IS NULL',
    await sha256(token), 'access', now());
  if (!row) return null;
  return { ...row, zotero_key: await decrypt(row.zotero_key_enc, env) };
}

const ACTIONS = {
  zotero_search: [
    'search_items','search_by_tag','search_by_citation_key','advanced_search','semantic_search','update_search_database','get_search_database_status',
  ],
  zotero_retrieval: [
    'get_item_metadata','get_item_fulltext','get_attachment_path','get_collections','get_collection_items','get_item_children','get_items_children','get_tags','list_libraries','list_groups','list_feeds','get_feed_items','get_recent','get_item_related','list_top','list_trash','list_deleted','list_publications',
  ],
  zotero_write: [
    'create_collection','delete_collection','search_collections','manage_collections','add_by_doi','add_by_url','add_by_isbn','update_item','delete_item','find_duplicates','merge_duplicates','add_from_file','attach_file','add_item_relation','remove_item_relation','add_by_bibtex','add_by_csl_json','batch_update_tags','batch_update_extra',
  ],
  zotero_annotations: [
    'get_annotations','get_notes','search_notes','create_note','update_note','delete_note','create_annotation','create_area_annotation','get_page_layout','update_annotation','delete_annotation',
  ],
  zotero_pdf: ['read_pdf_pages','get_pdf_outline'],
  zotero_scite: ['enrich_item','enrich_search','check_retractions'],
  zotero_synthesis: ['synthesize_annotations','export_bibliography'],
  zotero_connectors: ['chatgpt_connector_search','connector_fetch'],
};
const READ_ACTIONS = new Set([
  'search_items','search_by_tag','search_by_citation_key','advanced_search','semantic_search','get_search_database_status',
  'get_item_metadata','get_item_fulltext','get_attachment_path','get_collections','get_collection_items','get_item_children','get_items_children','get_tags','list_libraries','list_groups','list_feeds','get_feed_items','get_recent','get_item_related','list_top','list_trash','list_deleted','list_publications',
  'search_collections','find_duplicates','get_annotations','get_notes','search_notes','get_page_layout','get_pdf_outline','read_pdf_pages','enrich_item','enrich_search','check_retractions','synthesize_annotations','export_bibliography','chatgpt_connector_search','connector_fetch','get_current_time',
]);
const DESTRUCTIVE_ACTIONS = new Set(['delete_collection','delete_item','delete_note','delete_annotation','merge_duplicates','add_from_file']);
function actionDescription(tool, action) {
  const base = {
    zotero_search: 'Search and maintain the Zotero search layer. semantic_search reports the edge fallback when no vector index is configured.',
    zotero_retrieval: 'Read metadata, collections, children, full text, feeds, recent items, and library information from the connected Zotero library.',
    zotero_write: 'Create, update, delete, import, attach, relate, and deduplicate Zotero items and collections. Confirm destructive actions first.',
    zotero_annotations: 'Read and write Zotero notes and PDF annotation child items.',
    zotero_pdf: 'Read Zotero-indexed full text and expose PDF capability status. Exact page-layout extraction requires a PDF engine outside the Worker.',
    zotero_scite: 'Enrich DOI-bearing items with Scite public citation tallies and editorial notices.',
    zotero_synthesis: 'Export bibliography and produce deterministic annotation summaries without sending library text to a third-party model.',
    zotero_connectors: 'Compatibility helpers for connector-style search and fetch requests.',
  }[tool] || 'Zotero operation';
  return `${base} Action: ${action}.`;
}
function commonProperties() {
  return {
    action: { type: 'string', description: 'One action from the tool action list.' },
    item_key: { type: 'string' }, item_keys: { type: 'array', items: { type: 'string' } },
    collection_key: { type: 'string' }, collection_keys: { type: 'array', items: { type: 'string' } },
    parent_key: { type: 'string' }, query: { type: 'string' }, tag: { type: 'string' },
    limit: { type: 'integer', minimum: 1, maximum: 100 }, start: { type: 'integer', minimum: 0 },
    sort: { type: 'string' }, direction: { type: 'string', enum: ['asc','desc'] },
    qmode: { type: 'string' }, item_type: { type: 'string' }, format: { type: 'string' },
    data: { type: 'object' }, payload: { type: 'object' }, items: { type: 'array', items: { type: 'object' } },
    conditions: { type: 'array', items: { type: 'object' } }, operation: { type: 'string' },
    title: { type: 'string' }, name: { type: 'string' }, url: { type: 'string' }, doi: { type: 'string' }, isbn: { type: 'string' },
    bibtex: { type: 'string' }, csl_json: { type: 'object' }, note: { type: 'string' },
    content: { type: 'string' }, annotation_text: { type: 'string' }, annotation_comment: { type: 'string' },
    annotation_type: { type: 'string' }, page_label: { type: 'string' }, position: { type: 'object' },
    version: { type: 'integer' }, item_id: { type: 'string' }, duplicate_key: { type: 'string' }, master_key: { type: 'string' },
    library_id: { type: 'string' }, library_type: { type: 'string' }, include_children: { type: 'boolean' },
    pages: { type: 'array', items: { type: 'integer' } }, max_items: { type: 'integer' },
  };
}
function toolDefinition(name) {
  const properties = commonProperties();
  properties.action.enum = ACTIONS[name];
  const isReadOnly = ACTIONS[name].every(x => READ_ACTIONS.has(x));
  return {
    name,
    description: `${actionDescription(name, 'one of the supported actions')} Available actions: ${ACTIONS[name].join(', ')}.`,
    inputSchema: { type: 'object', properties, required: ['action'], additionalProperties: true },
    annotations: { readOnlyHint: isReadOnly, destructiveHint: !isReadOnly },
  };
}
function toolsList() { return Object.keys(ACTIONS).map(toolDefinition); }
function normalizeOutput(value) {
  if (Array.isArray(value)) return { items: value };
  if (value && typeof value === 'object') return value;
  return { result: value };
}
function mcpToolResult(value) {
  const structured = normalizeOutput(value);
  return { content: [{ type: 'text', text: JSON.stringify(structured) }], structuredContent: structured };
}
function requireAction(args) {
  const action = text(args.action);
  if (!action) throw new Error('action is required');
  return action;
}
function requireItemKey(args) {
  const k = text(args.item_key || args.item_id).trim();
  if (!k) throw new Error('item_key is required');
  return k;
}
function requireCollectionKey(args) {
  const k = text(args.collection_key).trim();
  if (!k) throw new Error('collection_key is required');
  return k;
}
function queryOptions(args, defaults = {}) {
  const out = { limit: clampInt(args.limit, 1, 100, defaults.limit || 25), start: clampInt(args.start, 0, 1000000, 0) };
  for (const k of ['sort','direction','qmode','itemType','tag','since','format','includeTrashed']) if (args[k] !== undefined) out[k] = args[k];
  if (args.item_type) out.itemType = args.item_type;
  return out;
}
function unwrapItem(item) { return item?.data ? item : item; }
function itemTitle(item) { return text(item?.data?.title || item?.title); }
function itemDOI(item) { return text(item?.data?.DOI || item?.DOI).trim().replace(/^https?:\/\/doi\.org\//i, ''); }
function itemYear(item) {
  const date = text(item?.data?.date || item?.date);
  const m = date.match(/\b(19|20)\d{2}\b/);
  return m ? m[0] : '';
}
function normalizeTitle(title) { return text(title).toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(); }
function relationUrl(grant, key) {
  const owner = grant.library_type === 'group' ? 'groups' : 'users';
  return `http://zotero.org/${owner}/${grant.library_id}/items/${String(key).toUpperCase()}`;
}

async function retrieveAction(grant, action, args) {
  const key = grant.zotero_key;
  const opts = queryOptions(args);
  if (action === 'get_item_metadata') return apiResult(await zoteroFetch(key, 'GET', itemPath(grant, requireItemKey(args))));
  if (action === 'get_item_fulltext') return apiResult(await zoteroFetch(key, 'GET', itemPath(grant, requireItemKey(args), '/fulltext')));
  if (action === 'get_attachment_path') {
    const item = (await zoteroFetch(key, 'GET', itemPath(grant, requireItemKey(args)))).data;
    return { item_key: item?.key, title: itemTitle(item), filename: item?.data?.filename || null, content_type: item?.data?.contentType || null, api_file_url: item?.links?.enclosure?.href || item?.links?.self?.href + '/file' || null, note: 'A Worker cannot expose a local Zotero desktop path; use the Web API file endpoint.' };
  }
  if (action === 'get_collections') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/collections', { query: opts }));
  if (action === 'get_collection_items') return apiResult(await zoteroFetch(key, 'GET', collectionPath(grant, requireCollectionKey(args), '/items'), { query: opts }));
  if (action === 'get_item_children') return apiResult(await zoteroFetch(key, 'GET', itemPath(grant, requireItemKey(args), '/children'), { query: opts }));
  if (action === 'get_items_children') {
    const keys = Array.isArray(args.item_keys) ? args.item_keys.slice(0, 20) : [];
    if (!keys.length) throw new Error('item_keys is required');
    const items = [];
    for (const k of keys) items.push({ parent_key: k, children: (await zoteroFetch(key, 'GET', itemPath(grant, k, '/children'), { query: opts })).data });
    return { items, count: items.length };
  }
  if (action === 'get_tags') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/tags', { query: opts }));
  if (action === 'list_groups') {
    if (!grant.zotero_user_id) return { items: [], note: 'The API key did not return a user ID.' };
    return apiResult(await zoteroFetch(key, 'GET', '/users/' + encodeURIComponent(grant.zotero_user_id) + '/groups', { query: opts }));
  }
  if (action === 'list_libraries') {
    const current = { type: grant.library_type, id: grant.library_id, current: true };
    let groups = [];
    if (grant.zotero_user_id) {
      try { groups = (await zoteroFetch(key, 'GET', '/users/' + encodeURIComponent(grant.zotero_user_id) + '/groups', { query: opts })).data || []; }
      catch { groups = []; }
    }
    return { current, groups: groups.map(g => ({ id: g.id, name: g.name, type: 'group' })) };
  }
  if (action === 'list_feeds') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/feeds', { query: opts }));
  if (action === 'get_feed_items') {
    const feedKey = text(args.item_key || args.feed_key);
    if (!feedKey) throw new Error('feed_key or item_key is required');
    return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/feeds/' + encodeURIComponent(feedKey) + '/items', { query: opts }));
  }
  if (action === 'get_recent') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items/top', { query: { ...opts, sort: args.sort || 'dateModified', direction: args.direction || 'desc' } }));
  if (action === 'list_top') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items/top', { query: opts }));
  if (action === 'list_trash') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items/trash', { query: opts }));
  if (action === 'list_deleted') return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/deleted', { query: opts }));
  if (action === 'list_publications') {
    if (grant.library_type !== 'user') throw new Error('Publications are available only for user libraries');
    return apiResult(await zoteroFetch(key, 'GET', '/users/' + encodeURIComponent(grant.library_id) + '/publications/items', { query: opts }));
  }
  if (action === 'get_item_related') {
    const item = (await zoteroFetch(key, 'GET', itemPath(grant, requireItemKey(args)))).data;
    const related = item?.data?.relations || {};
    return { item_key: item?.key, relations: related, relation_urls: Object.values(related).flatMap(v => Array.isArray(v) ? v : [v]) };
  }
  throw new Error('Unsupported retrieval action: ' + action);
}

async function searchAction(grant, action, args) {
  const key = grant.zotero_key;
  const opts = queryOptions(args);
  if (action === 'search_items' || action === 'chatgpt_connector_search') {
    const query = text(args.query).trim();
    if (!query) throw new Error('query is required');
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...opts, q: query, qmode: args.qmode || 'everything' } });
    return { ...apiResult(result), query, mode: 'zotero_web_api' };
  }
  if (action === 'search_by_tag') {
    const tag = text(args.tag).trim();
    if (!tag) throw new Error('tag is required');
    return apiResult(await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...opts, tag } }));
  }
  if (action === 'search_by_citation_key') {
    const query = text(args.query || args.citation_key).trim();
    if (!query) throw new Error('query or citation_key is required');
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...opts, q: query, qmode: 'everything' } });
    const items = Array.isArray(result.data) ? result.data.filter(item => /citation key\s*:/i.test(text(item?.data?.extra)) || text(item?.data?.citationKey).toLowerCase().includes(query.toLowerCase())) : [];
    return { items, count: items.length, query, mode: 'citation_key_filter' };
  }
  if (action === 'advanced_search') {
    const conditions = Array.isArray(args.conditions) ? args.conditions.slice(0, 20) : [];
    const q = conditions.map(c => text(c.value)).filter(Boolean).join(' ');
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...opts, q, qmode: 'everything' } });
    let items = Array.isArray(result.data) ? result.data : [];
    for (const c of conditions) {
      const field = text(c.field || c.key).toLowerCase();
      const value = text(c.value).toLowerCase();
      if (!field || !value) continue;
      items = items.filter(item => text(item?.data?.[field]).toLowerCase().includes(value) || text(item?.data?.extra).toLowerCase().includes(value));
    }
    return { items, count: items.length, conditions, mode: 'api-query-plus-edge-filter' };
  }
  if (action === 'semantic_search') {
    const query = text(args.query).trim();
    if (!query) throw new Error('query is required');
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...opts, q: query, qmode: 'everything' } });
    return { ...apiResult(result), query, mode: 'keyword_fallback', semantic_index: false, note: 'ChromaDB and sentence-transformers are not run inside Workers Free. This is a Zotero Web API keyword fallback until an external vector index is explicitly configured.' };
  }
  if (action === 'get_search_database_status') return { enabled: false, backend: 'none', mode: 'cloudflare-free-edge', reason: 'The original ChromaDB local index cannot run in a stateless Worker.' };
  if (action === 'update_search_database') return { updated: false, enabled: false, blocked: true, reason: 'Full semantic indexing requires a separate PDF/text extraction and vector backend; not silently enabled on the free Worker.' };
  if (action === 'connector_fetch') {
    const k = requireItemKey(args);
    return apiResult(await zoteroFetch(key, 'GET', itemPath(grant, k)));
  }
  throw new Error('Unsupported search action: ' + action);
}

async function getItem(grant, key) { return (await zoteroFetch(grant.zotero_key, 'GET', itemPath(grant, key))).data; }
async function createItems(grant, payload, parentKey) {
  const list = Array.isArray(payload) ? payload.slice(0, 50) : [payload];
  if (!list.length) throw new Error('payload is empty');
  if (parentKey) for (const item of list) item.parentItem = parentKey;
  return apiResult(await zoteroFetch(grant.zotero_key, 'POST', libraryRoot(grant) + '/items', { body: list, headers: zoteroWriteHeaders() }));
}
function buildArticleFromCrossref(work, doi) {
  const msg = work?.message || work || {};
  return {
    itemType: msg.type === 'book' ? 'book' : 'journalArticle',
    title: msg.title?.[0] || doi,
    DOI: doi,
    URL: msg.URL || `https://doi.org/${doi}`,
    abstractNote: msg.abstract || '',
    publicationTitle: msg['container-title']?.[0] || '',
    volume: text(msg.volume), issue: text(msg.issue), pages: text(msg.page),
    publisher: text(msg.publisher), date: msg.published?.['date-parts']?.[0]?.join('-') || '',
    creators: [...(msg.author || [])].map(a => ({ creatorType: 'author', firstName: text(a.given), lastName: text(a.family || a.name) })).filter(a => a.firstName || a.lastName),
  };
}
async function fetchCrossref(doi) {
  const r = await fetch('https://api.crossref.org/works/' + encodeURIComponent(doi), { headers: { Accept: 'application/json', 'User-Agent': 'Robbanin-Zotero-MCP/' + VERSION } });
  if (!r.ok) throw new Error('Crossref metadata lookup failed: ' + r.status);
  return r.json();
}
async function fetchIsbn(isbn) {
  const clean = text(isbn).replace(/[^0-9Xx]/g, '');
  if (!clean) throw new Error('isbn is required');
  const r = await fetch('https://openlibrary.org/api/books?bibkeys=ISBN:' + encodeURIComponent(clean) + '&format=json&jscmd=data', { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error('Open Library lookup failed: ' + r.status);
  const d = await r.json();
  return d['ISBN:' + clean] || null;
}
function mapIsbn(book, isbn) {
  return {
    itemType: 'book', title: text(book?.title, isbn), ISBN: isbn, URL: book?.url || '', publisher: text(book?.publishers?.[0]?.name),
    date: text(book?.publish_date), numPages: text(book?.number_of_pages),
    creators: (book?.authors || []).map(a => ({ creatorType: 'author', firstName: text(a.name).split(' ').slice(0,-1).join(' '), lastName: text(a.name).split(' ').slice(-1)[0] })).filter(a => a.lastName),
  };
}
function parseBibtex(input) {
  const source = text(input);
  const head = source.match(/@([^{]+)\{\s*([^,]+),/i);
  if (!head) throw new Error('Invalid BibTeX');
  const fields = {};
  const re = /([A-Za-z][\w-]*)\s*=\s*(?:\{([^{}]*)\}|"([^"]*)"|([^,\n]+))/g;
  let m;
  while ((m = re.exec(source))) fields[m[1].toLowerCase()] = text(m[2] || m[3] || m[4]).trim();
  const creators = text(fields.author).split(/\s+and\s+/i).map(a => {
    const p = a.includes(',') ? a.split(',').map(x => x.trim()) : a.trim().split(/\s+/);
    return { creatorType: 'author', firstName: p.length > 1 ? p.slice(0, -1).join(' ') : '', lastName: p.length > 1 ? p.at(-1) : p[0] };
  }).filter(x => x.lastName);
  const type = head[1].toLowerCase();
  return { itemType: type.includes('book') ? 'book' : type.includes('inproceedings') ? 'conferencePaper' : 'journalArticle', title: fields.title || head[2], DOI: fields.doi || '', date: fields.year || '', publicationTitle: fields.journal || fields.booktitle || '', volume: fields.volume || '', issue: fields.number || '', pages: fields.pages || '', publisher: fields.publisher || '', creators };
}
function mapCsl(csl) {
  const x = csl?.[0] || csl || {};
  return {
    itemType: x.type === 'book' ? 'book' : x.type === 'chapter' ? 'bookSection' : 'journalArticle', title: text(x.title), DOI: text(x.DOI || x.doi), URL: text(x.URL || x.url), abstractNote: text(x.abstract), publicationTitle: text(x['container-title']), volume: text(x.volume), issue: text(x.issue), page: text(x.page), publisher: text(x.publisher), date: x.issued?.['date-parts']?.[0]?.join('-') || text(x.issued),
    creators: (x.author || []).map(a => ({ creatorType: 'author', firstName: text(a.given), lastName: text(a.family || a.literal) })).filter(a => a.firstName || a.lastName),
  };
}
function dataForUpdate(args) {
  const d = args.data && typeof args.data === 'object' ? { ...args.data } : { ...args };
  for (const k of ['action','item_key','item_id','version','payload','data']) delete d[k];
  return d;
}

async function writeAction(grant, action, args) {
  const key = grant.zotero_key;
  if (action === 'create_collection') {
    const name = text(args.name || args.title).trim();
    if (!name) throw new Error('name is required');
    return apiResult(await zoteroFetch(key, 'POST', libraryRoot(grant) + '/collections', { body: [{ name, parentCollection: text(args.parent_collection || '') }], headers: zoteroWriteHeaders() }));
  }
  if (action === 'delete_collection') {
    const ck = requireCollectionKey(args); const current = await zoteroFetch(key, 'GET', collectionPath(grant, ck));
    await zoteroFetch(key, 'DELETE', collectionPath(grant, ck), { headers: zoteroWriteHeaders(current.data?.version) });
    return { ok: true, deleted_collection: ck };
  }
  if (action === 'search_collections') {
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/collections', { query: queryOptions(args) });
    const q = text(args.query || args.name).toLowerCase();
    const items = q ? (result.data || []).filter(x => text(x?.data?.name).toLowerCase().includes(q)) : result.data;
    return { items, count: items.length, query: q };
  }
  if (action === 'manage_collections') {
    const op = text(args.operation).toLowerCase();
    if (op === 'create') return writeAction(grant, 'create_collection', args);
    if (op === 'delete') return writeAction(grant, 'delete_collection', args);
    if (op === 'update') {
      const ck = requireCollectionKey(args); const current = await zoteroFetch(key, 'GET', collectionPath(grant, ck));
      const body = { data: { ...(current.data?.data || {}), ...(args.data || {}), name: args.name || args.data?.name || current.data?.data?.name } };
      return apiResult(await zoteroFetch(key, 'PUT', collectionPath(grant, ck), { body, headers: zoteroWriteHeaders(args.version || current.data?.version) }));
    }
    throw new Error('operation must be create, update, or delete');
  }
  if (action === 'update_item') {
    const ik = requireItemKey(args); const current = await getItem(grant, ik); const body = dataForUpdate(args);
    if (!Object.keys(body).length) throw new Error('data is required');
    return apiResult(await zoteroFetch(key, 'PATCH', itemPath(grant, ik), { body, headers: zoteroWriteHeaders(args.version || current?.version) }));
  }
  if (action === 'delete_item') {
    const ik = requireItemKey(args); const current = await getItem(grant, ik);
    await zoteroFetch(key, 'DELETE', itemPath(grant, ik), { headers: zoteroWriteHeaders(args.version || current?.version) });
    return { ok: true, deleted_item: ik };
  }
  if (action === 'add_by_doi') {
    const doi = text(args.doi).trim().replace(/^https?:\/\/doi\.org\//i, '');
    if (!doi) throw new Error('doi is required');
    return createItems(grant, buildArticleFromCrossref(await fetchCrossref(doi), doi));
  }
  if (action === 'add_by_url') {
    const url = text(args.url).trim();
    if (!/^https:\/\//i.test(url)) throw new Error('Only HTTPS URLs are accepted');
    return createItems(grant, { itemType: 'webpage', title: text(args.title, url), url, accessDate: new Date().toISOString() });
  }
  if (action === 'add_by_isbn') {
    const isbn = text(args.isbn).trim(); const book = await fetchIsbn(isbn);
    if (!book) throw new Error('No book metadata found for this ISBN');
    return createItems(grant, mapIsbn(book, isbn));
  }
  if (action === 'add_by_bibtex') return createItems(grant, parseBibtex(args.bibtex || args.content));
  if (action === 'add_by_csl_json') return createItems(grant, mapCsl(args.csl_json || args.data));
  if (action === 'attach_file') {
    const parent = text(args.parent_key || args.item_key).trim(); const url = text(args.url).trim();
    if (!parent || !url || !/^https:\/\//i.test(url)) throw new Error('parent_key and an HTTPS url are required');
    return createItems(grant, { itemType: 'attachment', linkMode: 'imported_url', title: text(args.title, url), url, contentType: text(args.content_type, 'application/pdf') }, parent);
  }
  if (action === 'add_from_file') return { ok: false, blocked: true, reason: 'Local file paths cannot reach a Cloudflare Worker. Use add_by_url, attach_file with an HTTPS URL, or upload through Zotero directly.' };
  if (action === 'add_item_relation' || action === 'remove_item_relation') {
    const ik = requireItemKey(args); const related = text(args.related_key || args.duplicate_key).trim(); if (!related) throw new Error('related_key is required');
    const current = await getItem(grant, ik); const relations = { ...(current?.data?.relations || {}) }; const url = relationUrl(grant, related);
    if (action === 'add_item_relation') relations[url] = url;
    else delete relations[url];
    return apiResult(await zoteroFetch(key, 'PATCH', itemPath(grant, ik), { body: { relations }, headers: zoteroWriteHeaders(args.version || current?.version) }));
  }
  if (action === 'batch_update_tags' || action === 'batch_update_extra') {
    const keys = Array.isArray(args.item_keys) ? args.item_keys.slice(0, 20) : [];
    if (!keys.length) throw new Error('item_keys is required');
    const results = [];
    for (const ik of keys) {
      const current = await getItem(grant, ik); const patch = action === 'batch_update_tags' ? { tags: args.tags || [] } : { extra: text(args.extra || args.content) };
      results.push({ item_key: ik, result: apiResult(await zoteroFetch(key, 'PATCH', itemPath(grant, ik), { body: patch, headers: zoteroWriteHeaders(current?.version) })) });
    }
    return { results, count: results.length };
  }
  if (action === 'find_duplicates') {
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items/top', { query: { limit: clampInt(args.limit, 1, 100, 100), sort: 'title', direction: 'asc' } });
    const groups = new Map();
    for (const item of result.data || []) { const k = normalizeTitle(itemTitle(item)) + '|' + itemYear(item); if (k !== '|') (groups.get(k) || groups.set(k, []).get(k)).push(item); }
    return { duplicate_groups: [...groups.entries()].filter(([, items]) => items.length > 1).map(([fingerprint, items]) => ({ fingerprint, items })), mode: 'title-year' };
  }
  if (action === 'merge_duplicates') {
    const master = text(args.master_key).trim(); const duplicate = text(args.duplicate_key || args.item_key).trim(); if (!master || !duplicate) throw new Error('master_key and duplicate_key are required');
    const a = await getItem(grant, master); const b = await getItem(grant, duplicate);
    const tags = [...new Map([...(a?.data?.tags || []), ...(b?.data?.tags || [])].map(x => [x.tag, x])).values()];
    const relations = { ...(b?.data?.relations || {}), ...(a?.data?.relations || {}) };
    await zoteroFetch(key, 'PATCH', itemPath(grant, master), { body: { tags, relations }, headers: zoteroWriteHeaders(a?.version) });
    await zoteroFetch(key, 'DELETE', itemPath(grant, duplicate), { headers: zoteroWriteHeaders(b?.version) });
    return { ok: true, master_key: master, deleted_duplicate: duplicate, merged: { tags: tags.length, relations: Object.keys(relations).length } };
  }
  throw new Error('Unsupported write action: ' + action);
}

async function annotationAction(grant, action, args) {
  const key = grant.zotero_key;
  if (action === 'get_annotations' || action === 'get_notes') {
    const parent = requireItemKey(args);
    const data = (await zoteroFetch(key, 'GET', itemPath(grant, parent, '/children'), { query: queryOptions(args) })).data || [];
    const wanted = action === 'get_annotations' ? 'annotation' : 'note';
    return { items: data.filter(x => x?.data?.itemType === wanted), parent_key: parent, item_type: wanted };
  }
  if (action === 'search_notes') {
    const result = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...queryOptions(args), itemType: 'note', q: text(args.query), qmode: 'everything' } });
    return apiResult(result);
  }
  if (action === 'create_note') {
    const parent = text(args.parent_key || args.item_key).trim(); if (!parent) throw new Error('parent_key is required');
    return createItems(grant, { itemType: 'note', note: text(args.note || args.content), tags: args.tags || [] }, parent);
  }
  if (action === 'update_note' || action === 'update_annotation') {
    const ik = requireItemKey(args); const current = await getItem(grant, ik);
    const patch = args.data && typeof args.data === 'object' ? args.data : { note: args.note || args.content, annotationComment: args.annotation_comment, annotationText: args.annotation_text, tags: args.tags };
    for (const k of Object.keys(patch)) if (patch[k] === undefined) delete patch[k];
    return apiResult(await zoteroFetch(key, 'PATCH', itemPath(grant, ik), { body: patch, headers: zoteroWriteHeaders(args.version || current?.version) }));
  }
  if (action === 'delete_note' || action === 'delete_annotation') {
    const ik = requireItemKey(args); const current = await getItem(grant, ik);
    await zoteroFetch(key, 'DELETE', itemPath(grant, ik), { headers: zoteroWriteHeaders(args.version || current?.version) });
    return { ok: true, deleted_item: ik };
  }
  if (action === 'create_annotation' || action === 'create_area_annotation') {
    const parent = text(args.parent_key || args.item_key).trim(); if (!parent) throw new Error('parent_key is required');
    return createItems(grant, { itemType: 'annotation', annotationType: action === 'create_area_annotation' ? 'image' : text(args.annotation_type, 'highlight'), annotationText: text(args.annotation_text || args.content), annotationComment: text(args.annotation_comment), annotationPageLabel: text(args.page_label), annotationPosition: args.position || {}, color: text(args.color), tags: args.tags || [] }, parent);
  }
  if (action === 'get_page_layout') return { supported: false, blocked: true, reason: 'PyMuPDF vector layout extraction is not part of the free Worker runtime.' };
  throw new Error('Unsupported annotation action: ' + action);
}

async function pdfAction(grant, action, args) {
  const key = grant.zotero_key;
  if (action === 'read_pdf_pages') {
    const item = requireItemKey(args);
    const full = (await zoteroFetch(key, 'GET', itemPath(grant, item, '/fulltext'))).data;
    return { item_key: item, requested_pages: args.pages || null, content: full?.content || full, mode: 'zotero_indexed_fulltext', page_accurate: false, note: 'The Worker can read Zotero-indexed full text. Exact page extraction and layout require the original PyMuPDF/pdf-inspector runtime.' };
  }
  if (action === 'get_pdf_outline') return { supported: false, blocked: true, reason: 'PDF outline extraction depends on PyMuPDF and is not run inside Workers Free.' };
  throw new Error('Unsupported PDF action: ' + action);
}
function normalizeDoi(v) { return text(v).trim().replace(/^https?:\/\/doi\.org\//i, '').replace(/^doi:\s*/i, ''); }
function doiFromItem(item) { return normalizeDoi(itemDOI(item)); }
async function sciteGet(path) {
  const r = await fetch(SCITE_BASE + path, { headers: { Accept: 'application/json', 'Content-Type': 'application/json' } });
  if (!r.ok) return null;
  try { return await r.json(); } catch { return null; }
}
async function scitePost(path, body) {
  const r = await fetch(SCITE_BASE + path, { method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) return null;
  try { return await r.json(); } catch { return null; }
}
function sciteFields(tally, paper) {
  return {
    supporting: tally?.supporting ?? 0,
    contrasting: tally?.contradicting ?? 0,
    mentioning: tally?.mentioning ?? 0,
    total_citing: tally?.citingPublications ?? tally?.total ?? 0,
    editorial_notices: (paper?.editorialNotices || []).map(n => ({ type: n.type || n.editorialNoticeType || 'notice', source_doi: n.sourceDoi || n.source || null })),
  };
}
async function sciteAction(grant, action, args) {
  const key = grant.zotero_key;
  if (action === 'enrich_item') {
    let doi = normalizeDoi(args.doi);
    let item = null;
    if (!doi && args.item_key) { item = await getItem(grant, args.item_key); doi = doiFromItem(item); }
    if (!doi) throw new Error('doi or an item_key containing a DOI is required');
    const [tally, paper] = await Promise.all([sciteGet('/tallies/' + encodeURIComponent(doi)), sciteGet('/papers/' + encodeURIComponent(doi))]);
    if (!tally && !paper) return { doi, found: false, note: 'No Scite data found or Scite was unavailable.' };
    return { doi, found: true, title: paper?.title || itemTitle(item) || null, scite: sciteFields(tally, paper) };
  }
  if (action === 'enrich_search' || action === 'check_retractions') {
    let items;
    if (args.item_keys?.length) items = []; else items = (await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query: { ...queryOptions(args), q: text(args.query), qmode: 'everything' } })).data || [];
    if (args.item_keys?.length) for (const k of args.item_keys.slice(0, 50)) { try { items.push(await getItem(grant, k)); } catch {} }
    const entries = items.map(item => ({ item, doi: doiFromItem(item) })).filter(x => x.doi).slice(0, 50);
    const dois = entries.map(x => x.doi);
    const [tallies, papers] = await Promise.all([scitePost('/tallies', dois), scitePost('/papers', dois)]);
    const tm = tallies?.tallies || {}, pm = papers?.papers || {};
    const out = entries.map(({ item, doi }) => ({ item_key: item.key, title: itemTitle(item), doi, scite: sciteFields(tm[doi] || tm[doi.toLowerCase()], pm[doi] || pm[doi.toLowerCase()]) }));
    if (action === 'check_retractions') return { items: out.filter(x => x.scite.editorial_notices.length), scanned: out.length };
    return { items: out, scanned: out.length };
  }
  throw new Error('Unsupported Scite action: ' + action);
}

async function synthesisAction(grant, action, args) {
  const key = grant.zotero_key;
  if (action === 'export_bibliography') {
    const keys = Array.isArray(args.item_keys) ? args.item_keys.filter(Boolean).slice(0, 50) : [];
    const format = text(args.format, 'bibtex');
    const query = { itemKey: keys.join(','), format, limit: keys.length || 50 };
    const r = await zoteroFetch(key, 'GET', libraryRoot(grant) + '/items', { query, raw: format !== 'json' });
    return { format, content: r.data, item_keys: keys };
  }
  if (action === 'synthesize_annotations') {
    const parent = requireItemKey(args);
    const data = (await zoteroFetch(key, 'GET', itemPath(grant, parent, '/children'), { query: { limit: 100 } })).data || [];
    const annotations = data.filter(x => x?.data?.itemType === 'annotation').map(x => ({ key: x.key, page: x.data.annotationPageLabel, text: x.data.annotationText, comment: x.data.annotationComment, type: x.data.annotationType })).filter(x => x.text || x.comment);
    return { item_key: parent, annotation_count: annotations.length, summary: annotations.map((x, i) => `${i + 1}. ${x.page ? '[p. ' + x.page + '] ' : ''}${x.text || ''}${x.comment ? ' | Comment: ' + x.comment : ''}`).join('\n'), mode: 'deterministic', note: 'No annotation text was sent to an external model.' };
  }
  throw new Error('Unsupported synthesis action: ' + action);
}

async function executeTool(tool, args, grant) {
  const action = requireAction(args);
  if (!ACTIONS[tool]?.includes(action)) throw new Error('Action is not supported by ' + tool + ': ' + action);
  if (tool === 'zotero_search' || tool === 'zotero_connectors') return searchAction(grant, action, args);
  if (tool === 'zotero_retrieval') return retrieveAction(grant, action, args);
  if (tool === 'zotero_write') return writeAction(grant, action, args);
  if (tool === 'zotero_annotations') return annotationAction(grant, action, args);
  if (tool === 'zotero_pdf') return pdfAction(grant, action, args);
  if (tool === 'zotero_scite') return sciteAction(grant, action, args);
  if (tool === 'zotero_synthesis') return synthesisAction(grant, action, args);
  throw new Error('Unknown tool: ' + tool);
}

const SERVER_INSTRUCTIONS = 'Cloudflare-native multi-user Zotero MCP. Connect your own Zotero API key through OAuth. The server exposes the Web API read/write surface in eight categorized tools. Credentials are encrypted at rest and never returned to the MCP client. Use zotero_search with action=semantic_search only as a keyword fallback unless a future vector backend is enabled. PDF page-accurate extraction and local file paths are intentionally reported as unsupported on the free Worker runtime. Confirm destructive write actions before calling them.';

async function handleMCP(request, env, grant) {
  if (request.method === 'GET') {
    return json({ ok: true, endpoint: '/mcp', transport: 'streamable-http', method: 'POST required' }, 405, { Allow: 'POST' });
  }
  if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, { Allow: 'POST' });
  let body;
  try { body = await request.json(); } catch { return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400); }
  if (Array.isArray(body)) {
    const results = [];
    for (const entry of body) {
      const response = await handleMCP(new Request(request.url, { method: 'POST', headers: request.headers, body: JSON.stringify(entry) }), env, grant);
      if (response.status !== 202 && response.status !== 204) results.push(await response.json());
    }
    return json(results);
  }
  const id = body.id ?? null;
  const method = body.method;
  if (method === 'initialize') {
    return json({ jsonrpc: '2.0', id, result: {
      protocolVersion: body.params?.protocolVersion || MCP_PROTOCOL,
      capabilities: { tools: {} },
      serverInfo: { name: SERVER_NAME, version: VERSION },
      instructions: SERVER_INSTRUCTIONS,
    } }, 200, { 'MCP-Protocol-Version': body.params?.protocolVersion || MCP_PROTOCOL });
  }
  if (method === 'notifications/initialized') return new Response(null, { status: 202, headers: CORS });
  if (method === 'ping') return json({ jsonrpc: '2.0', id, result: {} });
  if (method === 'tools/list') return json({ jsonrpc: '2.0', id, result: { tools: toolsList() } });
  if (method === 'tools/call') {
    const tool = text(body.params?.name);
    const args = body.params?.arguments && typeof body.params.arguments === 'object' ? body.params.arguments : {};
    try {
      const result = await executeTool(tool, args, grant);
      return json({ jsonrpc: '2.0', id, result: mcpToolResult(result) });
    } catch (e) {
      return json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: text(e.message, 'Tool failed') }], isError: true } });
    }
  }
  return json({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + text(method) } }, 200);
}

function unauthorized(request, env) {
  const base = baseUrl(request, env);
  return json({ error: 'unauthorized', error_description: 'Bearer access token required' }, 401, {
    'WWW-Authenticate': `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource", scope="mcp"`,
  });
}
function health(env) {
  return {
    ok: true,
    server: SERVER_NAME,
    version: VERSION,
    tools: toolsList().length,
    actions: Object.values(ACTIONS).reduce((n, a) => n + a.length, 0),
    storage: { d1_configured: !!env.ZOTERO_DB, encryption_configured: !!env.ENCRYPTION_KEY },
    capabilities: {
      web_api_crud: true,
      oauth_multi_user: true,
      pdf_indexed_fulltext: true,
      pdf_page_layout: false,
      local_file_import: false,
      semantic_vector_index: false,
      scite_public_enrichment: true,
    },
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try {
      const oauth = await handleOAuth(request, env, url);
      if (oauth) return oauth;
      if (path === '/healthz' || (path === '/' && request.method === 'GET')) return json(health(env));
      if ((path === '/mcp' || path === '/') && (request.method === 'POST' || request.method === 'GET')) {
        const grant = await authenticate(request, env);
        if (!grant) return unauthorized(request, env);
        return handleMCP(request, env, grant);
      }
      return json({ error: 'not_found' }, 404);
    } catch (e) {
      return json({ error: text(e.message, 'Internal error') }, e.status && e.status >= 400 && e.status < 600 ? e.status : 500);
    }
  },
};

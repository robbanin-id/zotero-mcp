# Zotero MCP

A multi-user, read/write remote MCP server for Zotero on Cloudflare Workers Free. It is a Cloudflare-native JavaScript reimplementation guided by the functional surface of [`54yyyu/zotero-mcp`](https://github.com/54yyyu/zotero-mcp), not a Python runtime port.

Live endpoint: `https://zotero-mcp.robbanin-id.workers.dev/mcp`
Canonical repository: `https://github.com/robbanin-id/zotero-mcp`

## Current state

- Streamable HTTP MCP plus OAuth 2.1, dynamic client registration, PKCE S256, refresh rotation, opaque bearer tokens, and revocation.
- Eight categorized umbrella tools with 64 actions.
- BYO Zotero API key per user, encrypted with AES-GCM before D1 storage. The key is never returned to the MCP client, placed in an MCP header, logged, or committed.
- Cloudflare D1 database: `zotero-mcp-db` (`b2844768-26c3-414f-ad64-bfc023c799b9`).
- No Zotero Desktop process is required.

## All-libraries access

The authorization form defaults to **All libraries accessible to this key**. The server validates the key's personal-library permission and reads Zotero's `/keys/<key>` `access.groups` map. It discovers the personal library and only the group libraries allowed by that key.

- Search actions fan out across the discovered libraries and annotate each item with `mcp_library: { type, id, name }`.
- `list_libraries` returns the resolved personal and group targets.
- Item, collection, note, annotation, PDF, and write actions default to the personal library. To target a group, pass both `library_type: "group"` and the numeric `library_id`.
- If a key has a per-group read-only permission, all-libraries onboarding rejects it because this server is intentionally read/write. Update the key at <https://www.zotero.org/settings/keys> or use a narrower single-library grant.
- Zotero may return a user ID with a decimal suffix; the server normalizes it before building library URLs.

## Capability boundary on Workers Free

Supported through the Zotero Web API:

- Search, metadata, collections, tags, children, recent items, library discovery, and connector-compatible search/fetch.
- Item, collection, note, annotation, relation, DOI/URL/ISBN/BibTeX/CSL writes.
- Duplicate detection and bounded merge.
- Zotero-indexed full-text retrieval.
- Public Scite enrichment and bibliography export.

Reported as unavailable or explicitly bounded rather than silently misrepresented:

- Local Zotero file paths and local-file import.
- PyMuPDF/pdf-inspector page-layout and exact PDF page extraction.
- ChromaDB/sentence-transformers local semantic indexing.

`semantic_search` uses a clearly labelled Zotero keyword fallback until an external per-user vector backend is explicitly configured.

## Setup from zero

1. Create a D1 database and apply [`schema.sql`](./schema.sql).
2. Copy [`wrangler.example.toml`](./wrangler.example.toml) to `wrangler.toml`, set the Worker URL and D1 ID, and use the current compatibility date.
3. Set an encryption secret, for example `openssl rand -hex 32`, with `wrangler secret put ENCRYPTION_KEY`. Do not paste the generated value into chat or GitHub.
4. Deploy with `npx wrangler deploy`.
5. If upgrading an existing database created before all-libraries support, run this migration once in the D1 console:

   ```sql
   ALTER TABLE grants ADD COLUMN all_libraries INTEGER NOT NULL DEFAULT 0;
   ```

6. Verify `/healthz`, OAuth metadata, DCR, the 401 challenge, the authorization form, token exchange, `tools/list`, library discovery, and a read operation.

The complete API key belongs only in the OAuth form at `/authorize`. Never put it into GitHub, Worker variables, MCP headers, logs, or chat.

## OAuth and MCP endpoints

- `GET /.well-known/oauth-authorization-server`
- `GET /.well-known/oauth-protected-resource`
- `POST /register`
- `GET /authorize`, then `POST /authorize`
- `POST /token`
- `POST /revoke`
- MCP at `POST /mcp` or the root POST endpoint

PKCE S256 is mandatory. Refresh tokens rotate. Access and refresh token hashes are stored, not the raw tokens.

## Tool catalog

The compact catalog keeps context overhead low while preserving the action surface:

- `zotero_search`
- `zotero_retrieval`
- `zotero_write`
- `zotero_annotations`
- `zotero_pdf`
- `zotero_scite`
- `zotero_synthesis`
- `zotero_connectors`

Call `tools/list` for the current action enum and call an umbrella tool with `{ "action": "...", ... }`. Search across all libraries is available for search, tag, citation-key, advanced, semantic-fallback, and Scite search actions. Specific-library operations accept `library_type` and `library_id`.

## Tests and verification

Local regression tests use a fake Zotero API and SQLite D1 shim. They verify OAuth/PKCE, encrypted grants, token exchange, tool discovery, all-libraries discovery, cross-library fan-out, and explicit group routing:

```bash
node tests/oauth.mjs
node tests/all-libraries.mjs
```

The live Worker has also been verified without exposing the key:

- `/healthz`: D1 and encryption configured, 8 tools, 64 actions, all-libraries and cross-library search enabled.
- DCR, authorization form, PKCE token exchange, `tools/list`: successful.
- Real key: personal library plus four permitted group libraries discovered.
- Real cross-library search: five upstream library calls returned HTTP 200.
- Explicit group-library collection read: HTTP 200.
- No live write probe was run against the user's library to avoid creating test data; the write contract and payloads are covered by local tests and the key's Zotero permissions are checked during onboarding.

## Security and operational boundaries

- OAuth grants are isolated per user and access/refresh tokens are hashed.
- Zotero keys are encrypted at rest with a Worker secret and decrypted only for the upstream request.
- Worker logs must not include request bodies, API keys, or bearer tokens.
- Cloudflare Free limits CPU time, request size, and storage; large PDF extraction and vector indexing remain outside this Worker until a compatible isolated backend is chosen.

# Zotero MCP

Multi-user OAuth 2.1 remote MCP server for Zotero on Cloudflare Workers Free.

## Architecture

- Cloudflare Worker handles Streamable HTTP MCP and OAuth 2.1.
- Each user brings a Zotero API key and library ID.
- Zotero keys are validated for library and write permission, then encrypted with AES-GCM before storage.
- D1 stores OAuth clients, one-time authorization requests/codes, grants, and hashed access/refresh tokens.
- No Zotero desktop process is required.
- The catalog has eight categorized umbrella tools and 64 actions, based on the functional surface of `54yyyu/zotero-mcp`.

## Capability boundary on Workers Free

Supported directly through the Zotero Web API:

- search, metadata, collections, tags, children, recent and library reads;
- item, collection, note, annotation, relation, import-by-DOI/URL/ISBN/BibTeX/CSL writes;
- duplicate detection and bounded merge;
- Zotero-indexed full-text retrieval;
- public Scite enrichment and bibliography export.

Intentionally reported as unavailable rather than silently misrepresented:

- local Zotero file paths and local file import;
- PyMuPDF/pdf-inspector page-layout and exact PDF page extraction;
- ChromaDB/sentence-transformers local semantic index.

`semantic_search` currently uses a clearly labelled Zotero keyword fallback. A future vector backend must be added only after its Cloudflare Free availability, quota, and per-user isolation are verified.

## Initial setup

1. Create a D1 database and apply `schema.sql`.
2. Copy `wrangler.example.toml` to `wrangler.toml` and set the database ID.
3. Set `ENCRYPTION_KEY` as a 32-byte hex Worker secret.
4. Deploy with a compatibility date.
5. Verify `/healthz`, OAuth metadata, DCR, 401 challenge, authorization form, token exchange, `tools/list`, and one read plus one write against a test Zotero library.

The complete API key belongs only in the OAuth form at `/authorize`. Never put it into GitHub, Worker variables, MCP headers, logs, or chat.

## OAuth client flow

- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`
- `POST /register`
- `GET /authorize` then `POST /authorize`
- `POST /token`
- `POST /revoke`
- MCP at `/mcp` or the root POST endpoint

PKCE S256 is mandatory. Refresh tokens rotate. Access tokens are opaque and only their SHA-256 hashes are stored.

## Verification notes

A local smoke suite verifies health, 401 metadata, DCR, PKCE, encrypted grant storage, token exchange, tools/list, per-user grant resolution, and a fake Zotero search. Live validation must use a dedicated Zotero test library and must not log or paste the API key.

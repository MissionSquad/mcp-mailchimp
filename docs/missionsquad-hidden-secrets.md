# MissionSquad hidden secret injection: refactor guide for `mcp-mailchimp`

This is the package-specific implementation guide for moving the Mailchimp MCP server
onto MissionSquad hidden secret injection. It is grounded in the reviewed code in
`src/mailchimp_mcp_server/server.py` and is meant to be executable without guessing policy.

## 1. Current state (before the refactor)

- Runtime: Python, official `mcp` SDK (`MCPServer` on 2.x, `FastMCP` on 1.x). Not
  `@missionsquad/fastmcp`, so there is no `context.extraArgs`.
- Auth: one process-global default key read at import time from `MAILCHIMP_API_KEY`, plus an
  env-era multi-account registry built from `MAILCHIMP_API_KEY_<NAME>` variables.
- Every one of the 228 tools takes a visible `account: str | None` selector that picks an entry
  from that registry. No tool declares an `apiKey`-style field, so the tool schemas are already
  auth-free. The `account` value is a non-secret name, not credential material.
- Safety flags (`MAILCHIMP_READ_ONLY`, `MAILCHIMP_DRY_RUN`) are process-global env values, with
  per-named-account overrides.
- `mc_request` and `_guard_write` are the two chokepoints; both call `_resolve_account`.
- One pooled `requests.Session` per account **name** (`_SESSIONS`), which on a shared server
  would be one session for every user because all injected users resolve to `default`.
- Startup performs no network call. The process already starts with no key present; the
  first tool call returns an error dict.

### Runtime prerequisite finding

The `mcp` SDK validates tool arguments through a pydantic model (`ArgModelBase`) whose config
does not set `extra`, so pydantic's default (`ignore`) silently drops undeclared keys before the
tool body runs. An injected `apiKey` would therefore be discarded. Registering `secretNames` is
not enough on its own; an equivalent hidden-argument path had to be introduced first.

Verified interception point (both SDK lines):

- mcp 2.x: `MCPServer._handle_call_tool` calls `self.call_tool(name, arguments, context)`.
- mcp 1.x: `FastMCP._setup_handlers` registers the bound `self.call_tool` at construction.

A subclass that overrides `call_tool` sees the raw `tools/call` arguments before validation.
Sync tools run on an anyio worker thread on 2.x; `contextvars` values set in the override are
visible there and are isolated between concurrent calls (verified empirically on mcp 2.2.0).

## 2. Target contract

Hidden values are injected per tool call by `mcp-api` and model one execution target per call.

| Hidden name | Required | Kind | Meaning |
|---|---|---|---|
| `apiKey` | yes | secret | Mailchimp API key, `<key>-<dc>`. The datacenter is derived from the suffix. |
| `readOnly` | no | hidden parameter | `true`/`false`. Blocks write tools for this user. |
| `dryRun` | no | hidden parameter | `true`/`false`. Write tools return a preview instead of calling the API. |

Precedence per field, on every call: hidden value, then environment fallback, then a
user-facing error (for the key) or `false` (for the flags).

Rules:

- Hidden values are read only through one resolver (`_resolve_account`), which reads the
  per-call context variable populated by the `call_tool` override.
- When a hidden `apiKey` is present, the visible `account` argument must be omitted or
  `"default"`. Any other name returns a user-facing error; the env-era multi-account registry
  is a local standalone feature and is never consulted for an injected user.
- Environment fallback stays exactly as documented for local standalone use.
- Hidden keys never reach the tool function's arguments: the override strips every undeclared
  key from `arguments` before the SDK validates them, so no tool can forward them upstream.
- Nothing logs hidden values. The audit log receives visible params/body only; `apiKey` and
  `api_key` are additionally in the redaction set as defense in depth.
- Connection pooling is keyed by a SHA-256 fingerprint of the key (bounded LRU), never by the
  account name, so users on a shared process never share a `requests.Session`.

## 3. File-by-file changes

`src/mailchimp_mcp_server/server.py`

1. Add `HIDDEN_ARG_NAMES` (`apiKey`, `readOnly`, `dryRun`) and a `contextvars.ContextVar`
   holding the undeclared arguments of the current call.
2. Add `HiddenArgsServer(MCPServer)` overriding `call_tool`. It splits the raw arguments into
   declared (per `tool.parameters["properties"]`) and undeclared, stores the undeclared set in
   the context variable for the duration of the call, and forwards only the declared ones.
3. Instantiate `mcp = HiddenArgsServer(...)`.
4. Add `_read_hidden_string` / `_read_hidden_flag` validators and `_resolve_hidden`, raising
   `HiddenConfigError` with remediation text for wrong types, empty strings, and bad flag values.
5. Rewrite `_resolve_account` to apply the precedence above and to reject named accounts when a
   key is injected. Include `credentials` (`injected` / `environment`) in the resolved dict so
   error messages can give the right remediation.
6. `mc_request`: missing-key error names both remediations (MissionSquad secret and env var).
   `_session_for` takes the API key and keys the pool by fingerprint with an LRU bound.
7. `_guard_write`: read-only error text depends on whether the flag came from the platform or
   the environment.
8. `list_accounts`: with an injected key, return only the single injected target and a
   top-level `credentials: "injected"`; otherwise the existing env listing plus
   `credentials: "environment"`. Never returns key material.
9. `_AUDIT_REDACT`: add `apiKey` and `api_key`.
10. `ping` and `get_account_info`: return the error object from `mc_request` instead of
    discarding it, so a missing or invalid injected key is a visible, user-facing error on the
    two tools users reach for first.

`missionsquad.json` (new): the `mcp-api` server registration payload with `secretNames` and
`secretFields`.

`README.md`: new "MissionSquad (hidden secret injection)" section covering hidden keys, env
fallback, precedence, and local standalone usage.

`CHANGELOG.md`: Unreleased entry.

`tests/test_hidden_secrets.py` (new): see section 5.

## 4. Anti-patterns removed or ruled out

- Process-global authenticated state shared across users: the pooled session was keyed by
  account name (`default` for every injected user). Now keyed by key fingerprint.
- Auth resolved from `process.env`-style globals only: env is now a fallback behind the
  per-call hidden value.
- Pass-through of injected keys into upstream bodies: impossible by construction because the
  override drops undeclared keys before the tool runs, and a regression test proves it.
- Logging full argument objects after injection: the audit log only ever sees the visible
  params/body; a test asserts the injected key never appears on stderr.

## 5. Test plan

- hidden `apiKey` overrides `MAILCHIMP_API_KEY` (auth tuple and datacenter-derived URL)
- env fallback used when no hidden value is present
- missing key: user-facing error naming both remediations
- wrong type, empty string, whitespace-only: user-facing errors, no network call
- `readOnly` / `dryRun`: override env flags; invalid values rejected
- `account` selector: rejected with an injected key unless omitted or `default`
- no tool schema declares any hidden name
- injected values are not forwarded in query params or JSON bodies, and not in dry-run previews
- injected values never appear in audit log output
- session pool isolated per key; same key reuses the session
- two users with different keys on the same process each hit Mailchimp with their own key;
  concurrent calls stay isolated
- end-to-end over real stdio: the installed entrypoint starts with no `MAILCHIMP_*` variables,
  serves `tools/list` without hidden fields, and a `tools/call` carrying `apiKey` resolves to
  the injected target

## 6. Validation criteria

- `uv run ruff check src/ tests/` passes
- `uv run pytest` passes on the installed `mcp` 2.x, and the suite also passes against the
  latest `mcp` 1.x
- `uv run python -c "from mailchimp_mcp_server.server import mcp"` passes with no env set
- the stdio end-to-end test above passes (real process, real transport)
- no hidden name appears in any tool schema
- the acceptance criteria in the MissionSquad handbook are all satisfied

## 7. Validation record

- `uv run ruff check src/ tests/`: clean
- `uv run pytest`: 237 passed on mcp 2.2.0; 237 passed on mcp 1.30.0 in a separate venv
- Import and console-script startup with an empty environment (`env -i`): the process starts,
  answers `initialize`, and resolves an injected `apiKey` / `readOnly` on `tools/call`
- Handbook audit script: no findings (it scans TypeScript only); the manual Python equivalent
  (environment reads, hidden-value reads, stderr writes, key usage, legacy endpoints) is clean
- No caches other than the per-key session pool remain; no background timers were introduced

# mcp-auth-proxy

A small local reverse proxy that sits between an MCP client and a remote MCP server that needs short-lived credentials (for example a server behind Google IAP). The client talks to `http://127.0.0.1:7600/` as if it were a normal MCP server. The proxy runs an allowlisted **strategy** command to generate credentials, caches them, refreshes them before they expire, and re-authenticates and retries if the upstream rejects them.

The proxy config only holds the strategies (fixed commands) and the hosts it may talk to. Everything else is chosen per request by the consumer through headers: which strategy to use, where to send the request, and where the credential goes.

```
MCP client ── X-Proxy-Strategy: payload-iap ───────────────► 127.0.0.1:7600 ──► https://payload.example.com/api/mcp
              X-Proxy-Target:   https://payload.example.com/api/mcp   │  fills {{token}} placeholders
              Proxy-Authorization: Bearer {{token}}                   └─ runs the strategy command when needed
```

Targets the MCP **streamable HTTP** transport. Written in Go (1.24+), macOS or Linux. The config file is validated with [zog](https://zog.dev), and the only dependencies are zog and a YAML parser.

## Quick start

```bash
go install github.com/Oudwins/mcp-auth-proxy/cmd/mcp-auth-proxy@latest
# or from a checkout: go build -o bin/mcp-auth-proxy ./cmd/mcp-auth-proxy

mkdir -p ~/.mcp-auth-proxy
cp examples/config.example.yaml ~/.mcp-auth-proxy/config.yaml
$EDITOR ~/.mcp-auth-proxy/config.yaml

mcp-auth-proxy check      # runs each strategy once, prints masked values and expiry
mcp-auth-proxy serve      # start the proxy
```

Consumer config (Claude Code style). Non-IAP headers such as an API key pass through unchanged:

```json
{
  "mcpServers": {
    "payload": {
      "type": "http",
      "url": "http://127.0.0.1:7600/",
      "headers": {
        "X-Proxy-Strategy": "example-iap",
        "X-Proxy-Target": "https://payload.example.com/api/mcp",
        "Proxy-Authorization": "Bearer {{token}}",
        "Authorization": "Bearer <api key>"
      }
    }
  }
}
```

## CLI

```
mcp-auth-proxy [serve] [-c path] [-p port] [--host addr] [--debug]
mcp-auth-proxy check [strategy...] [-c path]
mcp-auth-proxy --help | --version
```

- Config path: `-c`, else `$MCP_AUTH_PROXY_CONFIG`, else `~/.mcp-auth-proxy/config.yaml`.
- `serve` logs to stderr and shuts down cleanly on SIGINT and SIGTERM. `--debug` logs one line per proxied request (templated path, never credentials).
- `check` runs each strategy (or the named ones) once and prints masked values, expiry and where it came from, and the effective `allowedHosts`. Exit code 1 if any generator failed, 2 for config or usage errors.

## Configuration

YAML (JSON also parses). Unknown keys are ignored. Every string may contain `${env:NAME}`; a variable that is not set is a startup error naming every missing variable.

```yaml
listen:
  host: 127.0.0.1
  port: 7600
logLevel: info
maxBodyBytes: 26214400

allowedHosts:            # required, at least one
  - "*.example.com"

strategies:              # at least one
  example-iap:
    command: [gcloud, auth, print-identity-token, "--audiences=${env:IAP_AUDIENCE}"]
    output: token
    ttl: 55m
```

| Field | Default | Meaning |
| --- | --- | --- |
| `listen.host` | `127.0.0.1` | Bind address. Non-loopback addresses log a warning. |
| `listen.port` | `7600` | `0` picks a free port. |
| `logLevel` | `info` | `info` or `debug`. |
| `maxBodyBytes` | 25 MiB | Request bodies are buffered so they can be replayed after a refresh. Larger bodies get a 413. |
| `allowedHosts` | required | Hosts a target may point at, used by every strategy without its own list. |
| `strategies.<name>` | required | Name is `[A-Za-z0-9][A-Za-z0-9._-]*`. Strategies take no parameters; create another strategy instead. |
| `command` | required | A string (run through the shell) or an array (exec'd directly, no shell). |
| `output` | `token` | `token` or `json`, see below. |
| `ttl` | `300` | Lifetime to assume when the output does not say. |
| `refreshSkew` | `60` | Refresh this long before expiry. |
| `retryCooldown` | `5` | Minimum gap between a generator run and a rejection-triggered re-run. |
| `timeout` | `30` | The command and its children are killed after this. |
| `retryOnStatus` | `[401]` | Upstream statuses that trigger one re-authentication and replay. |
| `allowedHosts` (strategy) | global list | **Replaces** the global list for this strategy. |
| `cwd` | config file directory | Working directory for the command. Relative paths resolve against the config file. |
| `env` | `{}` | Extra environment for the command, merged over the proxy's environment. |

Durations (`ttl`, `refreshSkew`, `retryCooldown`, `timeout`) are a number of seconds or a string such as `500ms`, `30s`, `55m`, `1h`.

### allowedHosts syntax

`[http(s)://]host[:port]`, optionally with a leading `*.` wildcard.

- No scheme means https only. The port defaults to the scheme's default and must match exactly, so `http://localhost:3000` is a separate entry from `localhost`.
- `*.example.com` matches subdomains only, not `example.com` itself. It needs at least one dot after `*.` and cannot be used with IP addresses.
- Matching is on the hostname string, with no DNS lookups. It is checked on the target before any substitution.

## Strategy output contract

The command runs with the proxy's environment, plus the strategy `env`, plus:

| Variable | Value |
| --- | --- |
| `MCP_AUTH_PROXY_STRATEGY` | strategy name, so one script can serve several strategies |
| `MCP_AUTH_PROXY_FORCE_REFRESH` | `1` when the upstream just rejected the previous credentials, else `0`. Use it to bypass any cache your script keeps. |

It must exit 0 and print the credentials to stdout. On a non-zero exit the proxy returns a 502 `auth_command_failed` whose message contains the last part of stderr (token-looking values redacted), so print actionable errors there. Credentials are cached per strategy and shared across every target that uses it.

### `output: token` (default)

stdout is one bare token (surrounding whitespace trimmed, inner whitespace is an error). It becomes the `{{token}}` placeholder, so `gcloud auth print-identity-token` works as-is with no wrapper script.

### `output: json`

stdout is one JSON object:

```json
{
  "values": { "token": "eyJ...", "tenant": "acme" },
  "expiresAt": 1767225600,
  "expiresInSeconds": 3600
}
```

- `values` is required: a map of placeholder name to non-empty string without control characters. Names match `[A-Za-z_][A-Za-z0-9_]*`.
- `expiresAt` is optional: epoch **seconds** or an ISO 8601 string. A number more than about 400 days out is rejected as probably milliseconds.
- `expiresInSeconds` is optional, relative to when the output was parsed. If both are present, `expiresAt` wins.
- Other keys are rejected.

See `examples/auth/json-script.sh`.

### How expiry is decided

First match wins:

1. `expiresAt` or `expiresInSeconds` in the output.
2. The `exp` claim of a JWT found in any value (the last whitespace-separated part is tried). With several JWTs, the earliest.
3. `ttl`.

Credentials that are already expired when parsed are an error.

## Request format

Consumer headers:

| Header | Required | Meaning |
| --- | --- | --- |
| `X-Proxy-Strategy` | yes | Name of a configured strategy. |
| `X-Proxy-Target` | yes | Absolute `http(s)` URL of the upstream MCP endpoint. Its host must match the strategy's effective `allowedHosts`. |

Both are stripped before forwarding. All other client headers pass through, including `Authorization` and `Proxy-Authorization`.

The request path and query on the proxy URL are appended to the target (a bare `/` appends nothing, queries are merged).

### Placeholders

`{{name}}` is replaced by the credential value of that name in:

- any client header value (inserted as is), and
- the path and query of `X-Proxy-Target` (URL-encoded).

Never in the scheme or host: a `{{` there is rejected. Write `\{{` for a literal `{{`. Redirects are never followed.

A request that contains no placeholder anywhere is rejected with `no_placeholder` before the strategy command runs, which catches a forgotten `{{token}}` early.

Examples:

```
Proxy-Authorization: Bearer {{token}}
X-Tenant: {{tenant}}
X-Proxy-Target: https://api.example.com/mcp/{{tenant}}?access_token={{token}}
```

### Refresh behavior

- **Lazy:** nothing runs at startup. The command runs on the first request, and again on a request that arrives within `refreshSkew` of expiry.
- **Single flight:** concurrent requests share one generator run.
- **Stale fallback:** if a proactive refresh fails but the cached credentials have not expired yet, they are reused and a warning is logged.
- **Reactive:** if the upstream answers with a status in `retryOnStatus`, the proxy re-runs the command (`MCP_AUTH_PROXY_FORCE_REFRESH=1`), re-renders the request from the original templates and replays it once. It does not retry when another request already refreshed, when the last run was within `retryCooldown`, or when the new values are identical to the rejected ones. The upstream's response is then passed back unchanged, so a bad credential cannot cause a loop.

Methods, bodies and streaming responses (SSE) are passed through; the upstream request is aborted if the client disconnects. Rendered header values containing CR or LF are rejected.

`GET /_health` returns each strategy's effective `allowedHosts` and auth status. It never contains credential values.

Errors from the proxy itself are JSON `{"error":{"code":"...","message":"..."}}`:

| Status | Code | When |
| --- | --- | --- |
| 400 | `missing_strategy` / `unknown_strategy` | `X-Proxy-Strategy` is absent or not configured |
| 400 | `missing_target` / `invalid_target` | `X-Proxy-Target` is absent, malformed, has a fragment, or has a placeholder in its host |
| 400 | `unknown_placeholder` | a `{{name}}` the strategy did not produce (the message lists the available names) |
| 400 | `no_placeholder` | no `{{...}}` anywhere in the request |
| 403 | `target_not_allowed` | target host is not in the strategy's effective `allowedHosts` |
| 403 | `forbidden_host` | `Host` header is not a loopback name or the configured host (DNS rebinding guard) |
| 403 | `forbidden_origin` | request carries an `Origin` header (blocks browsers) |
| 413 | `body_too_large` | body exceeds `maxBodyBytes` |
| 502 | `auth_command_failed` | generator failed, timed out, or printed something unparseable |
| 502 | `upstream_unreachable` | could not connect to the upstream |

## Security model

- **No client authentication to the proxy.** Protection is the loopback bind, Host header checks and `Origin` rejection (DNS rebinding and browsers). Any local process that can reach the port can use your credentials for any allowed host. Only widen `listen.host` if you understand that.
- Consumers cannot run code: they only pick a strategy by name, and strategies take no parameters. The target is limited to `allowedHosts`, so credentials cannot be sent elsewhere.
- Credential values are never logged and never returned by `/_health` or `check`. Parse errors do not echo the command's output, and stderr shown in errors is redacted.
- Config is trusted input: `command` runs with your privileges. Keep the config file writable only by you. Do not put secrets in it, use `${env:NAME}` or let the command fetch them.

## Running in the background (macOS)

`examples/launchd/com.example.mcp-auth-proxy.plist` is a LaunchAgent template. Replace the `__HOME__` placeholder, put the binary at `~/.local/bin/mcp-auth-proxy` (or edit the path in the plist), copy the plist to `~/Library/LaunchAgents/`, then `launchctl bootstrap gui/$(id -u) <plist>`.

launchd starts jobs with a minimal `PATH`, so a command that calls `gcloud`, `jq` and similar needs `PATH` set in the strategy's `env` (the example config does this).

## Limitations

- Only streamable HTTP. Legacy HTTP+SSE servers that announce an absolute or root-relative endpoint URL will bypass the proxy.
- macOS and Linux only (the command's process group is killed on timeout).
- `gcloud` credentials themselves can still expire: when Application Default Credentials need a human, the proxy reports the `gcloud` error in the 502 and you run `gcloud auth application-default login` again.

## Development

```bash
go test -race ./...    # unit tests, plus e2e against a mock IAP-style MCP upstream
go vet ./...
go build -o bin/mcp-auth-proxy ./cmd/mcp-auth-proxy
```

The e2e suite never contacts a real upstream.

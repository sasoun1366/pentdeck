# pentdeck — internal network assessment

- **Scope:** Example: intranet web server
- **Authorization:** S. Shaghoulian — authority: example run — own lab host (recorded 2026-09-21T11:29:57Z)
- **Window:** 2026-09-21T11:29:57+00:00 → 2026-09-21T11:30:00+00:00
- **Hosts:** 1 up of 1 in scope
- **Checks run:** `ports`, `banner`, `http`, `tls`

| severity | count |
| --- | --- |
| critical | 0 |
| high | 0 |
| medium | 1 |
| low | 3 |
| info | 2 |

## Findings

### MEDIUM — Plain HTTP is served without redirecting to HTTPS (127.0.0.1:8123)

GET / answered 200 over http://127.0.0.1:8123

**Remediation:** Redirect all HTTP to HTTPS on this port (301), and make sure the credentials and session cookies never travel unencrypted.

### LOW — Clickjacking protection is missing (127.0.0.1:8123)

neither X-Frame-Options nor a CSP frame-ancestors directive is set

**Remediation:** Add `X-Frame-Options: DENY` (or a CSP frame-ancestors rule).

### LOW — Server header discloses its version (127.0.0.1:8123)

Server: SimpleHTTP/0.6 Python/3.13.14

**Remediation:** Hide the version in the server configuration and patch the version itself.

### LOW — X-Content-Type-Options is missing (127.0.0.1:8123)

the response has no x-content-type-options header

**Remediation:** Add `X-Content-Type-Options: nosniff` to stop MIME sniffing.

### INFO — 3 open TCP port(s) (127.0.0.1)

Ports answering a TCP connection: 22, 111, 8123

Evidence: `connect scan of 41 port(s)`

**Remediation:** Confirm every one of these is meant to be reachable from this network.

### INFO — HTTP 200 OK (127.0.0.1:8123)

server: SimpleHTTP/0.6 Python/3.13.14

## Checks not run

| check | reason |
| --- | --- |
| `dns-zone-transfer` | not requested for this run |
| `plaintext` | not requested for this run |

## Errors

- `127.0.0.1:8123: banner: ConnectionResetError: [Errno 104] Connection reset by peer`

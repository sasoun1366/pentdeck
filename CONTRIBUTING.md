# Contributing to pentdeck

Thanks for looking. This project is deliberately small: one file, no runtime
dependencies, and a test suite that runs offline in a few seconds. Keep it that
way and your patch is easy to accept.

## The ground rules

1. **No new runtime dependencies.** `pentdeck.py` must keep working with a bare
   Python 3.9 install. If a change seems to need a library, open an issue first —
   the answer is usually a smaller version of the change.
2. **One file stays one file.** The tool is meant to be copyable to a jump host.
3. **Python 3.9 syntax.** No `X | Y` type unions at runtime, no `match`,
   no `tomllib`. `from __future__ import annotations` is already in place for
   the annotations themselves.
4. **Errors are statuses, not tracebacks.** A network problem is a `Result` with
   a status, never an exception that reaches the user.

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The suite is offline by design: certificates in `tests/certs/` (one valid until
2036, one that expired in 2020), and local TLS servers started by the tests
themselves. If your change needs a new fixture certificate, generate it with
`openssl` and commit the PEM, not a script that downloads anything.

A change to the checks should keep the test that compares our reading of the
validity window against `openssl x509 -enddate` — that test is the only thing
standing between the hand-written parser and a silent off-by-one-day bug.

## What is welcome

- More checks that fit the "one screen" idea (certificate chain length, key size,
  SAN coverage) as long as they do not need a new dependency.
- Better `UNTRUSTED` reasons if you can get them out of the `ssl` module without
  a hand-written chain validator.
- Fixes for edge cases: unusual time formats in `notAfter`, IPv6 literals,
  IDN host names, proxies.
- Documentation fixes, especially in the "Limitations" section — a wrong claim
  there is worse than a missing feature.

## What will be refused

- Anything that turns `pentdeck` into a monitoring *server* (a daemon, a database,
  a web UI). That is a different project.
- Payloads, telemetry, "phone home" behaviour of any kind.
- Dependencies added for convenience.

## Reporting a bug

Include the command, the host type (web server, mail, router, …), your Python
version and the exact output. If the certificate is private, reproduce it with a
self-signed one generated like this:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

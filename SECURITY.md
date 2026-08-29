# Security policy

## Supported versions

GraceGraph is an alpha research tool. Only the newest GitHub release receives
security fixes.

## Reporting

Use GitHub private vulnerability reporting for security-sensitive issues. Do not open
a public issue containing credentials, restricted data, private research records, or
an unpatched exploit. Ordinary correctness and documentation issues may use the
public issue tracker.

## Security boundary

GraceGraph parses untrusted JSON and reads caller-declared local files. It rejects
duplicate JSON keys, unknown schema fields, unsafe relative paths, symlinked or
hard-linked inputs, exact-inventory drift, capsule member drift, and attempts to raise
the fixed alpha boundary.

`PASS_SEALED_BYTES_ONLY` is not authentication or semantic replay. Hashes establish
byte identity, not truth, permission, independence, or currentness. GraceGraph is not
a sandbox, a signature system, a medical device, an experiment authorizer, or a
substitute for accountable scientific review.

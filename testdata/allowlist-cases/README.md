# Allowlist test cases

Every string in this folder is high-entropy or secret-shaped but is **not** a real
secret: UUIDs, git SHAs, sha256 sums, and canonical `EXAMPLE`/placeholder values.

`shhscan fs testdata/allowlist-cases` must report **zero findings**. The integration
test `internal/sources/integration_test.go` asserts exactly that — it's how we prove
the false-positive filtering actually works.

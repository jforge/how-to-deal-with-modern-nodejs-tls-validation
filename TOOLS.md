# Shell Tools Reference

This document covers the shell scripts in this repository, their options, and usage examples.

---

## `check-node-tls-certs.sh`

Validates a certificate chain against multiple OpenSSL verification modes to predict whether it will be accepted by Node.js.

### Synopsis

```
check-node-tls-certs.sh -s <server.pem> -r <roots.pem> [-i <intermediates.pem>] [-p <purpose>]
```

### Options

| Option | Required | Description |
|--------|----------|-------------|
| `-s <file>` | Yes | Leaf/server certificate PEM file |
| `-r <file>` | Yes | Trusted root CA bundle PEM file |
| `-i <file>` | No | Intermediate CA bundle PEM file |
| `-p <purpose>` | No | Verification purpose (default: `sslserver`) |
| `-h` | No | Show help |

Valid values for `-p`: `sslserver`, `sslclient`, `crlsign`, `any`, etc. (any purpose accepted by `openssl verify -purpose`).

### What it checks

The script runs four categories of checks and prints a summary at the end:

1. **Plain verify** — basic chain trust and validity. Equivalent to what Node.js does at a minimum. If this fails, the problem is a broken chain, wrong root CA, expired cert, or wrong purpose.

2. **X.509 strict verify** (`-x509_strict`) — RFC 5280 structural conformance. Catches missing extensions such as Basic Constraints, Key Usage (Certificate Sign), Subject Key Identifier, and Authority Key Identifier. Node.js 24.5+ enables this by default.

3. **Security level 0–5** (`-auth_level`) — cryptographic strength checks. Node.js defaults to level 2 (≥112-bit security: RSA/DSA/DH ≥ 2048 bits, ECC ≥ 224 bits, SHA-1 not accepted for certificates).

4. **CA certificate diagnosis** — if strict verify fails, each CA cert in the root and intermediate bundles is inspected individually to report which extensions are missing.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Script completed (individual checks may still have failed — read the output) |
| `1` | Server certificate is expired |
| `2` | Usage error (bad arguments, missing files, `openssl` not found) |

### Examples

**Server certificate with separate intermediates:**
```bash
./check-node-tls-certs.sh \
  -s cert-check/new-certs/cybus_server.crt \
  -r cert-check/new-certs/cybus_ca.crt \
  -i cert-check/new-certs/cybus_intermediate.crt
```

**Client certificate:**
```bash
./check-node-tls-certs.sh \
  -s client.pem \
  -r roots.pem \
  -i intermediates.pem \
  -p sslclient
```

**Root CA bundle only (no intermediates):**
```bash
./check-node-tls-certs.sh -s server.pem -r ca-bundle.pem
```

### Reading the output

```
Certificate summary         — subject, issuer, validity dates
Key/signature summary       — algorithm, key size, critical extensions
== Plain verify ==          — PASS/FAIL for basic chain trust
== X.509 strict verify ==   — PASS/FAIL for RFC 5280 conformance
== CA Certificate Diagnosis == — listed only when strict verify fails
== Security level N ==      — PASS/FAIL for each cryptographic strength level

Interpretation
--------------
- Plain verification passed/failed ...
- Security level results: level 0 [PASS/FAIL] ... <-- Node.js default at level 2
- Overall: looks good for modern Node.js defaults.
```

The `Interpretation` section at the bottom summarises what the results mean in plain language and whether the chain will work with Node.js default settings.

---

## `cert-info.sh`

Inspects and displays the contents of a PEM-encoded certificate or certificate chain.

### Synopsis

```
cert-info.sh <pem-file> <mode> [full-chain]
```

### Arguments

| Position | Values | Description |
|----------|--------|-------------|
| 1 | `<path>` | PEM file to inspect (required) |
| 2 | `-s` \| `-m` \| `-l` | Output detail level (required) |
| 3 | `true` \| `false` | Show all certs in a chain file (default: `false`) |

**Detail levels:**

| Flag | Name | Output |
|------|------|--------|
| `-s` | Short | Subject, issuer, validity dates, SANs, certificate type |
| `-m` | Medium | Full text output, headers/version/serial/signature/public key/aux fields suppressed |
| `-l` | Long | Complete `openssl x509 -text` dump |

### Examples

**Quick summary of a single certificate:**
```bash
./cert-info.sh cert-check/new-certs/cybus_server.crt -s
```

**Detailed view of a CA certificate:**
```bash
./cert-info.sh cert-check/new-certs/cybus_ca.crt -m
```

**Full dump:**
```bash
./cert-info.sh cert-check/new-certs/cybus_server.crt -l
```

**Inspect every certificate in a bundle file:**
```bash
./cert-info.sh cert-check/new-certs/cybus_ca.crt -s true
```

---

## Quick reference

| Script | What it answers |
|--------|----------------|
| `check-node-tls-certs.sh` | Will Node.js accept this cert chain? Which check fails and why? |
| `cert-info.sh` | What is in this PEM file? |

# Node.js TLS Validation (in Docker): X.509 Strictness, OpenSSL Security Levels, and Safe CA Trust Configuration

This is a short reference for modern Node.js TLS validation
together with newer OpenSSL security level defaults.

Some containerized products and services are regularly updated due to
vulnerabilities or a general upgrade of a runtime environment or framework
without completely considering the security implications.

This includes, for instance, products containerized with Node.js base images
Since Node.js 24.5 there's been a [new default security level](https://nodejs.org/docs/latest/api/tls.html#openssl-security-level)
which can challenge older X.509 certificate chains.

## "Strict validation"

There are **two different things** that often get called “strict validation,” and they are not the same:

**1. OpenSSL X.509 strict mode** (`X509_V_FLAG_X509_STRICT`, CLI: `-x509_strict`)  
Without strict mode, OpenSSL still does normal certificate validation: 
it builds a chain, checks purpose/trust, checks validity dates, and verifies signatures. 
With strict mode, OpenSSL additionally turns off compatibility workarounds for broken certificates 
and enforces extra RFC 5280 well-formedness checks. 

The OpenSSL docs list examples: 
- CA certs must explicitly carry `keyUsage`, 
- `pathLenConstraint` must only appear where valid,
- issuer names must not be empty,
- certain subject/SAN combinations must not be empty,
- `signatureAlgorithm` must match the certificate signature, 
- X.509v3 certs generally need `authorityKeyIdentifier`, 
- and X.509v3 CA certs need `subjectKeyIdentifier`. 

ref: [docs.openssl.org](https://docs.openssl.org/master/man1/openssl-verification-options/)

**2. OpenSSL security level** (`@SECLEVEL=n`)  
This is a different control. It governs the minimum acceptable cryptographic strength for keys,
signatures, protocols, and ciphers.

Current Node TLS docs say the default security level is **2**,
and show lowering it with `@SECLEVEL=X` when legacy interoperability is needed.

OpenSSL documents level 2 as requiring roughly **112 bits** of security,
which means RSA/DSA/DH keys shorter than **2048 bits**
and ECC keys shorter than **224 bits** are rejected;
RC4, SSLv3, and TLS compression are also disallowed.

ref: [Node.js](https://nodejs.org/api/tls.html)

### Official Node.js Docker images

For **official Node.js Docker images**,`X509_V_FLAG_X509_STRICT` itself didn't become the default. 

In fact, a Node maintainer explicitly stated that `X509_V_FLAG_X509_STRICT` is **disabled by default**, 
and the `docker-node` repository says it ships upstream Node releases into Docker images **unchanged**.

ref: [GitHub+1](https://github.com/nodejs/node/pull/37938)

What **did** change and can be considered "stricter", is the newer OpenSSL policy in newer Node releases.
Node **24.5.0**, released on **2025-07-31**, upgraded Node to **OpenSSL 3.5.1**. 

A Node issue documented that the OpenSSL default security level change to **2** was included in Node **24.5**, 
and current Node docs reflect level 2 as the default. 
So, the crypto-policy strictness was increased in **`node:24.5.0` and later** and should be confused with `X509_STRICT`. 

ref: [Node.js+2GitHub+2](https://nodejs.org/en/blog/release/v24.5.0)


### How to use Node without strict validation by default without skipping validation:

#### If you mean X.509 strict mode:

In stock Node, you likely do **nothing**, because stock Node is already **not** enabling `X509_V_FLAG_X509_STRICT` by default.
The right fix is usually to correct the trust chain or CA store, not to turn verification off.

ref: [GitHub+1](https://github.com/nodejs/node/pull/37938)

#### If you mean trust-store problems
such as private PKI, self-signed corporate roots, or missing internal CA roots:  

Keep validation on and **add the CA properly**. 
Node supports `NODE_EXTRA_CA_CERTS=file` to extend the default trust roots, 
`--use-openssl-ca` / `--use-system-ca` to use OS trust, and `tls.setDefaultCACertificates()` 
with `tls.getCACertificates('system')` to make system CAs the default in-process. 

ref: [Node.js+3](https://nodejs.org/api/cli.html)


For a Docker image, the two clean patterns are:
```dockerfile
# Pattern A: append your private CA to Node's default trust
COPY company-root-ca.pem /opt/certs/company-root-ca.pem
ENV NODE_EXTRA_CA_CERTS=/opt/certs/company-root-ca.pem
```

```dockerfile
# Pattern B: trust the OS CA store and tell Node to use it
COPY company-root-ca.pem /usr/local/share/ca-certificates/company-root-ca.crt
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV NODE_USE_SYSTEM_CA=1
```

`NODE_EXTRA_CA_CERTS` **extends** trust; it does not disable verification. 

`NODE_USE_SYSTEM_CA=1` is available in newer Node releases, while `--use-openssl-ca` is the older long-standing option. 

ref: [Node.js+2](https://nodejs.org/api/cli.html)


#### If you mean crypto-policy strictness

and you need legacy certs/keys to keep working while still validating certificates:  

Lower the OpenSSL security level to **1**, not to `rejectUnauthorized=false`. 
Node documents this via `@SECLEVEL=X`, either per context or globally with `--tls-cipher-list`. 

ref: [Node.js+1](https://nodejs.org/api/tls.html)

Global default in Docker:

```dockerfile
ENV NODE_OPTIONS="--tls-cipher-list=DEFAULT@SECLEVEL=1"
```

Per client/server in code:

```JavaScript
import https from 'node:https';

const agent = new https.Agent({
  ciphers: 'DEFAULT@SECLEVEL=1',
});

https.get('https://legacy.example.internal', { agent }, (res) => {
  console.log(res.statusCode);
});
```

That keeps certificate verification on. 
The setting that disables verification is `rejectUnauthorized: false`; 
Node’s TLS docs show `rejectUnauthorized` defaults to `true`.

ref: [Node.js+2](https://nodejs.org/api/tls.html)

### Summary

* **Want “no X509 strict”?** Stock Node already does that by default. [GitHub](https://github.com/nodejs/node/pull/37938)
* **Want internal certs to validate?** Add the right CA with `NODE_EXTRA_CA_CERTS`, `--use-system-ca`, or `tls.setDefaultCACertificates()`. [Node.js+2](https://nodejs.org/api/cli.html)
* **Want legacy weak cert/key material to work while still validating?** Use `DEFAULT@SECLEVEL=1`, globally or per TLS context. [Node.js+1](https://nodejs.org/api/tls.html)


## Short reference for Node.js TLS certificate validation in Docker

The key distinction for practical checks is this:

- `-x509_strict` tests RFC-style certificate correctness, 
- `-auth_level 2` tests whether the chain is strong enough for Node’s current default OpenSSL security level.

### What changed in official Node Docker images

The official `node` Docker images are upstream Node packaged for Docker;
The relevant pivot is **`node:24.5.0` and later**.
It's about **security level**, not Docker enabling `X509_STRICT`.

### Node version matrix

* **`node:20.x`**  
  No evidence that X.509 strict mode is enabled by default. 
  For trust customization, the portable options are `NODE_EXTRA_CA_CERTS` and `--use-openssl-ca`. 
  System-store integration described in current Node guidance starts later than this line.
  
  ref: [Node.js+3](https://github.com/nodejs/node/pull/37938)

* **`node:22.0` to `22.14`**  
  Same practical position as Node 20 for this topic: no evidence of default X.509 strict mode; 
  use `NODE_EXTRA_CA_CERTS` or `--use-openssl-ca` when you need additional trust anchors.
  
  ref: [Node.js+2](https://github.com/nodejs/node/pull/37938)

* **`node:22.15` to `22.18`**  
  `--use-system-ca` is available, so Node can trust the OS CA store in addition to bundled Mozilla roots, 
  but the `NODE_USE_SYSTEM_CA=1` environment variable was added later.
 
  ref: [Node.js+1](https://nodejs.org/learn/http/enterprise-network-configuration)

* **`node:22.19+`**  
  `NODE_USE_SYSTEM_CA=1` is available, and `--use-system-ca` remains available. 
  This is a good baseline if you want Dockerized Node to use the host/container trust store without disabling verification.
  
  ref: [Node.js+1](https://nodejs.org/api/cli.html)

* **`node:24.0` to `24.4`**  
  `--use-system-ca` is available. No evidence of default X.509 strict mode. 
  The big security-level behavior change tied to OpenSSL 3.5.1 is not the documented pivot here yet. 
  
  ref: [Node.js+2](https://nodejs.org/learn/http/enterprise-network-configuration)

* **`node:24.5+`**  
  This is the important breakpoint for the stricter default behavior: 
  Node 24.5 ships with OpenSSL 3.5.1, Node’s TLS docs now describe the default security level as **2**, 
  and Node 24.5 also introduced `tls.setDefaultCACertificates()` for programmatic default trust configuration. 
  `NODE_USE_SYSTEM_CA=1` arrives in **24.6.0**.
 
  ref: [Node.js+3](https://nodejs.org/ta/blog/release/v24.5.0)


### What to do for “no strict validation by default” without turning validation off

If your goal is **“do not disable certificate verification but avoid failures caused by missing enterprise roots or private PKI”**, use one of these:

#### A. Add your CA bundle

```Bash
export NODE_EXTRA_CA_CERTS=/path/to/company-ca-bundle.pem
node app.js
```

`NODE_EXTRA_CA_CERTS` **extends** Node’s trust store. It does not disable verification. It is ignored only when you explicitly pass a `ca` option for that particular TLS/HTTPS connection. [Node.js](https://nodejs.org/api/cli.html)

#### B. Use the system CA store

```Bash
node --use-system-ca app.js
```

Or, on newer releases:

```Bash
export NODE_USE_SYSTEM_CA=1
node app.js
```

Node's enterprise networking docs say Node normally uses bundled Mozilla roots by default
and does **not** consult the OS store unless you opt in. 

When enabled, system CAs are used **in addition to** bundled roots.

ref: [Node.js+2](https://nodejs.org/learn/http/enterprise-network-configuration)

#### C. Programmatic default CA configuration

```JavaScript
import tls from 'node:tls';

tls.setDefaultCACertificates([
  ...tls.getCACertificates('default'),
  ...tls.getCACertificates('system'),
]);
```

This keeps verification enabled and changes the default trust set 
for later TLS connections that do not provide their own `ca`.

ref: [Node.js+1](https://nodejs.org/ta/blog/release/v24.5.0)

#### D. If the problem is security level, not trust

Do **not** use `rejectUnauthorized: false`. 
Keep verification on, but lower the OpenSSL security level explicitly:

```Bash
export NODE_OPTIONS="--tls-cipher-list=DEFAULT@SECLEVEL=1"
node app.js
```

Or per connection/context:

```JavaScript
import https from 'node:https';

const agent = new https.Agent({
  ciphers: 'DEFAULT@SECLEVEL=1',
});

https.get('https://legacy.example.internal', { agent }, (res) => {
  console.log(res.statusCode);
});
```

Node documents `@SECLEVEL=X` for this purpose, and the TLS APIs still verify 
certificates unless `rejectUnauthorized` is set to `false`. 
The default behavior is verification **on**. 

ref: [Node.js+1](https://nodejs.org/api/tls.html)

### How to check whether Node would reject a certificate set because of the security level

Use **OpenSSL `verify`** first. It is the cleanest offline pre-check.

#### Basic chain check

```Bash
openssl verify \
  -purpose sslserver \
  -show_chain \
  -CAfile roots.pem \
  -untrusted intermediates.pem \
  server.pem
```

#### X.509 strictness check

```Bash
openssl verify \
  -purpose sslserver \
  -x509_strict \
  -show_chain \
  -CAfile roots.pem \
  -untrusted intermediates.pem \
  server.pem
```

#### Node-24.5+-style security-level check

```Bash
openssl verify \
  -purpose sslserver \
  -auth_level 2 \
  -show_chain \
  -CAfile roots.pem \
  -untrusted intermediates.pem \
  server.pem
```

#### Comparison run

```Bash
openssl verify \
  -purpose sslserver \
  -auth_level 1 \
  -show_chain \
  -CAfile roots.pem \
  -untrusted intermediates.pem \
  server.pem
```

Interpretation:

* **plain verify passes, `-x509_strict` fails**  
  The cert chain is trusted enough to build, but the certs are not RFC-clean enough for strict X.509 mode.

  ref: [docs.openssl.org+1](https://docs.openssl.org/master/man1/openssl-verification-options/)

* **`-auth_level 1` passes, `-auth_level 2` fails**  
  This strongly points to a **security-level** rejection, which is exactly the category that matters for current Node defaults. 
  OpenSSL defines `-auth_level` as the minimum acceptable signature/public-key strength for chain verification. 

  ref: [docs.openssl.org+2](https://docs.openssl.org/master/man1/openssl-verification-options/)

* **both fail**  
  The problem is probably more basic: missing trust anchor, bad chain order, wrong issuer, expired cert, unsupported purpose, 
  or malformed certificate.

  ref: [docs.openssl.org+1](https://docs.openssl.org/3.6/man1/openssl-verify/)

### How to inspect the certs themselves

For each certificate:

```Bash
openssl x509 -in cert.pem -noout -text
```

Look at:

* `Signature Algorithm`
* `Public-Key`
* CA-related extensions like `Basic Constraints`, `Key Usage`, `Subject Key Identifier`, `Authority Key Identifier`

OpenSSL’s `x509 -text` output includes those details, and they are the fields most relevant to both `-x509_strict` and `-auth_level`.

ref: [docs.openssl.org+2](https://docs.openssl.org/3.0/man1/openssl-x509/?utm_source=chatgpt.com)

### Practical recommendation

For modern internal PKI in Docker, the safest default is:

```dockerfile
ENV NODE_USE_SYSTEM_CA=1
ENV NODE_EXTRA_CA_CERTS=/opt/certs/company-extra-roots.pem
```

Use that on **22.19+ / 24.6+**. On older lines, prefer:

```dockerfile
ENV NODE_EXTRA_CA_CERTS=/opt/certs/company-extra-roots.pem
```

Only drop to `DEFAULT@SECLEVEL=1` when the actual problem is legacy crypto strength, 
proven by the `openssl verify -auth_level 2` vs `-auth_level 1` comparison. 

ref: [Node.js+3](https://nodejs.org/api/cli.html)

## Tooling

The shell script is for offline triage of certificate sets. It runs:

* plain `openssl verify`
* `openssl verify -x509_strict`
* `openssl verify -auth_level 1`
* `openssl verify -auth_level 2`

That lets you distinguish:

* basic chain/trust failure
* strict X.509 conformance failure
* security-level rejection that would matter for modern Node defaults. 
  OpenSSL documents `-x509_strict` and `-auth_level` exactly for these purposes. 

  ref: [docs.openssl.org+2](https://docs.openssl.org/master/man1/openssl-verification-options/?utm_source=chatgpt.com)


Example usage:

```Bash
chmod +x ./check-node-tls-certs.sh
./check-node-tls-certs.sh -s server.pem -r roots.pem -i intermediates.pem
```

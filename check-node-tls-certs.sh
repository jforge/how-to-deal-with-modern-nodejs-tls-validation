#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  check-node-tls-certs.sh -s server.pem -r roots.pem [-i intermediates.pem] [-p sslserver]

Purpose:
  Check whether a certificate chain would likely fail in Node.js because of
  trust/chain problems, X.509 strictness, or OpenSSL security level.

Options:
  -s  Leaf/server certificate PEM file (required)
  -r  Trusted root CA bundle PEM file (required)
  -i  Intermediate CA bundle PEM file (optional)
  -p  Verification purpose (default: sslserver)
  -h  Show help

Examples:
  check-node-tls-certs.sh -s server.pem -r roots.pem -i intermediates.pem
  check-node-tls-certs.sh -s client.pem -r roots.pem -i intermediates.pem -p sslclient
USAGE
}

SERVER_CERT=""
ROOTS=""
INTERMEDIATES=""
PURPOSE="sslserver"

while getopts ":s:r:i:p:h" opt; do
  case "$opt" in
    s) SERVER_CERT="$OPTARG" ;;
    r) ROOTS="$OPTARG" ;;
    i) INTERMEDIATES="$OPTARG" ;;
    p) PURPOSE="$OPTARG" ;;
    h)
      usage
      exit 0
      ;;
    :) 
      echo "Error: option -$OPTARG requires an argument" >&2
      usage >&2
      exit 2
      ;;
    \?)
      echo "Error: invalid option -$OPTARG" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$SERVER_CERT" || -z "$ROOTS" ]]; then
  echo "Error: -s and -r are required" >&2
  usage >&2
  exit 2
fi

for f in "$SERVER_CERT" "$ROOTS"; do
  if [[ ! -f "$f" ]]; then
    echo "Error: file not found: $f" >&2
    exit 2
  fi
done

if [[ -n "$INTERMEDIATES" && ! -f "$INTERMEDIATES" ]]; then
  echo "Error: file not found: $INTERMEDIATES" >&2
  exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "Error: openssl not found in PATH" >&2
  exit 2
fi

OPENSSL_BASE=(openssl verify -purpose "$PURPOSE" -show_chain -CAfile "$ROOTS")
if [[ -n "$INTERMEDIATES" ]]; then
  OPENSSL_BASE+=( -untrusted "$INTERMEDIATES" )
fi
OPENSSL_BASE+=( "$SERVER_CERT" )

run_check() {
  local label="$1"
  shift
  local outfile
  outfile="$(mktemp)"
  echo
  echo "== $label =="
  if "$@" >"$outfile" 2>&1; then
    cat "$outfile"
    rm -f "$outfile"
    return 0
  else
    cat "$outfile"
    rm -f "$outfile"
    return 1
  fi
}

plain_ok=0
strict_ok=0
level1_ok=0
level2_ok=0

echo "Certificate summary"
echo "-------------------"
openssl x509 -in "$SERVER_CERT" -noout -subject -issuer -dates || true
echo
echo "Key/signature summary"
openssl x509 -in "$SERVER_CERT" -noout -text \
  | awk '
      /Signature Algorithm:/ && !sig++ { print }
      /Public-Key:/ { print }
      /X509v3 Basic Constraints:/ { print; getline; print }
      /X509v3 Key Usage:/ { print; getline; print }
      /X509v3 Subject Key Identifier:/ { print; getline; print }
      /X509v3 Authority Key Identifier:/ { print; getline; print }
    ' || true

if run_check "Plain verify" "${OPENSSL_BASE[@]}"; then
  plain_ok=1
fi

STRICT_CMD=(openssl verify -purpose "$PURPOSE" -x509_strict -show_chain -CAfile "$ROOTS")
LEVEL1_CMD=(openssl verify -purpose "$PURPOSE" -auth_level 1 -show_chain -CAfile "$ROOTS")
LEVEL2_CMD=(openssl verify -purpose "$PURPOSE" -auth_level 2 -show_chain -CAfile "$ROOTS")
if [[ -n "$INTERMEDIATES" ]]; then
  STRICT_CMD+=( -untrusted "$INTERMEDIATES" )
  LEVEL1_CMD+=( -untrusted "$INTERMEDIATES" )
  LEVEL2_CMD+=( -untrusted "$INTERMEDIATES" )
fi
STRICT_CMD+=( "$SERVER_CERT" )
LEVEL1_CMD+=( "$SERVER_CERT" )
LEVEL2_CMD+=( "$SERVER_CERT" )

if run_check "X.509 strict verify (-x509_strict)" "${STRICT_CMD[@]}"; then
  strict_ok=1
fi

if run_check "Security level 1 (-auth_level 1)" "${LEVEL1_CMD[@]}"; then
  level1_ok=1
fi

if run_check "Security level 2 (-auth_level 2)" "${LEVEL2_CMD[@]}"; then
  level2_ok=1
fi

echo
echo "Interpretation"
echo "--------------"

if [[ "$plain_ok" -eq 0 ]]; then
  echo "- Plain verification failed. This looks like a basic trust or chain issue."
  echo "  Check root CA, intermediates, issuer chain, validity dates, and purpose."
else
  echo "- Plain verification passed. The chain is basically trusted and usable."
fi

if [[ "$plain_ok" -eq 1 && "$strict_ok" -eq 0 ]]; then
  echo "- Plain verify passed but X.509 strict failed."
  echo "  This points to certificate structure / RFC-conformance issues, not basic trust."
fi

if [[ "$level1_ok" -eq 1 && "$level2_ok" -eq 0 ]]; then
  echo "- Auth level 1 passed but auth level 2 failed."
  echo "  This strongly suggests the chain is too weak for Node.js environments using SECLEVEL=2."
  echo "  Likely causes: RSA/DSA/DH key < 2048 bits, ECC key < 224 bits, or other weak crypto choices."
fi

if [[ "$plain_ok" -eq 1 && "$level2_ok" -eq 1 ]]; then
  echo "- The chain passed auth level 2."
  echo "  It is unlikely to be rejected by Node.js purely because of the default OpenSSL security level."
fi

if [[ "$plain_ok" -eq 1 && "$strict_ok" -eq 1 && "$level2_ok" -eq 1 ]]; then
  echo "- Overall: looks good for modern Node.js defaults."
fi

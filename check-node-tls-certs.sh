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

diagnose_ca_cert() {
  local cert_file="$1"
  local text
  text=$(openssl x509 -in "$cert_file" -noout -text 2>/dev/null)

  local found_issue=0

  # Basic Constraints
  if ! echo "$text" | grep -q "X509v3 Basic Constraints:"; then
    echo "    ISSUE: Missing X509v3 Basic Constraints extension"
    found_issue=1
  elif ! echo "$text" | grep -A2 "X509v3 Basic Constraints:" | grep -q "CA:TRUE"; then
    local bc_value
    bc_value=$(echo "$text" | grep -A2 "X509v3 Basic Constraints:" | grep -v "X509v3 Basic Constraints:" | head -1 | xargs)
    echo "    ISSUE: X509v3 Basic Constraints present but CA:TRUE is not set (found: ${bc_value:-<empty>})"
    found_issue=1
  fi

  # Key Usage
  if ! echo "$text" | grep -q "X509v3 Key Usage:"; then
    echo "    ISSUE: Missing X509v3 Key Usage extension (Certificate Sign required for CA)"
    found_issue=1
  elif ! echo "$text" | grep -A2 "X509v3 Key Usage:" | grep -q "Certificate Sign"; then
    local ku_value
    ku_value=$(echo "$text" | grep -A2 "X509v3 Key Usage:" | grep -v "X509v3 Key Usage:" | head -1 | xargs)
    echo "    ISSUE: X509v3 Key Usage present but Certificate Sign (keyCertSign) is not set (found: ${ku_value:-<empty>})"
    found_issue=1
  fi

  # Subject Key Identifier (required by RFC 5280 §4.2.1.2 for CA certs)
  if ! echo "$text" | grep -q "X509v3 Subject Key Identifier:"; then
    echo "    ISSUE: Missing X509v3 Subject Key Identifier (required by RFC 5280 for CA certs)"
    found_issue=1
  fi

  # Authority Key Identifier (required for non-self-signed certs per RFC 5280 §4.2.1.1)
  local subject issuer
  subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null)
  issuer=$(openssl x509 -in "$cert_file" -noout -issuer 2>/dev/null)
  if [[ "$subject" != "$issuer" ]] && ! echo "$text" | grep -q "X509v3 Authority Key Identifier:"; then
    echo "    ISSUE: Missing X509v3 Authority Key Identifier (required by RFC 5280 for non-self-signed CA certs)"
    found_issue=1
  fi

  if [[ "$found_issue" -eq 0 ]]; then
    echo "    (no structural issues detected)"
  fi
}

diagnose_bundle() {
  local file="$1"
  local label="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"

  awk -v dir="$tmpdir" '
    /-----BEGIN CERTIFICATE-----/ { idx++; outfile=dir "/" idx ".pem" }
    outfile { print > outfile }
    /-----END CERTIFICATE-----/ { close(outfile); outfile="" }
  ' "$file"

  for cert_file in "$tmpdir"/*.pem; do
    [[ -f "$cert_file" ]] || continue
    subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null)
    echo
    echo "  [$label] $subject"
    diagnose_ca_cert "$cert_file"
  done
  rm -rf "$tmpdir"
}

plain_ok=0
strict_ok=0
level_results=()   # indexed 0-5, value 1=pass 0=fail

echo "Certificate summary"
echo "-------------------"
openssl x509 -in "$SERVER_CERT" -noout -subject -issuer -dates || true

if ! openssl x509 -in "$SERVER_CERT" -noout -checkend 0 2>/dev/null; then
  echo
  echo "ERROR: Certificate is expired. Stopping."
  exit 1
fi

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
if [[ -n "$INTERMEDIATES" ]]; then
  STRICT_CMD+=( -untrusted "$INTERMEDIATES" )
fi
STRICT_CMD+=( "$SERVER_CERT" )

if run_check "X.509 strict verify (-x509_strict)" "${STRICT_CMD[@]}"; then
  strict_ok=1
else
  echo
  echo "== CA Certificate Diagnosis =="
  diagnose_bundle "$ROOTS" "Root CA"
  if [[ -n "$INTERMEDIATES" ]]; then
    diagnose_bundle "$INTERMEDIATES" "Intermediate CA"
  fi
fi

for lvl in 0 1 2 3 4 5; do
  LEVEL_CMD=(openssl verify -purpose "$PURPOSE" -auth_level "$lvl" -show_chain -CAfile "$ROOTS")
  if [[ -n "$INTERMEDIATES" ]]; then
    LEVEL_CMD+=( -untrusted "$INTERMEDIATES" )
  fi
  LEVEL_CMD+=( "$SERVER_CERT" )
  if run_check "Security level $lvl (-auth_level $lvl)" "${LEVEL_CMD[@]}"; then
    level_results[$lvl]=1
  else
    level_results[$lvl]=0
  fi
done

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
  echo "  See 'CA Certificate Diagnosis' above for the exact problem(s) found."
fi

# Security level descriptions for interpretation
level_desc=(
  [0]="no security constraints (everything permitted)"
  [1]=">=80-bit: RSA/DSA/DH>=1024, ECC>=160; SHA-1 allowed"
  [2]=">=112-bit: RSA/DSA/DH>=2048, ECC>=224; SHA-1 not for certs (Node.js default)"
  [3]=">=128-bit: RSA/DSA/DH>=3072, ECC>=256; SHA-256+"
  [4]=">=192-bit: RSA/DSA/DH>=7680, ECC>=384; SHA-384+"
  [5]=">=256-bit: RSA/DSA/DH>=15360, ECC>=512; SHA-512+"
)

highest_passing=-1
for lvl in 0 1 2 3 4 5; do
  if [[ "${level_results[$lvl]:-0}" -eq 1 ]]; then
    highest_passing=$lvl
  fi
done

echo "- Security level results:"
for lvl in 0 1 2 3 4 5; do
  if [[ "${level_results[$lvl]:-0}" -eq 1 ]]; then
    marker="PASS"
  else
    marker="FAIL"
  fi
  suffix=""
  if [[ "$lvl" -eq 2 ]]; then suffix=" <-- Node.js default"; fi
  echo "    level $lvl [$marker]  ${level_desc[$lvl]}${suffix}"
done

if [[ "$highest_passing" -eq -1 ]]; then
  echo "- WARN: Failed even at level 0. Something is fundamentally wrong with the chain."
elif [[ "$highest_passing" -eq 5 ]]; then
  echo "- Passes all security levels."
else
  next=$(( highest_passing + 1 ))
  echo "- Highest passing level: $highest_passing. Fails at level $next (${level_desc[$next]})."
  if [[ "$next" -le 2 ]]; then
    echo "  The chain will be rejected by Node.js (default SECLEVEL=2)."
  fi
fi

if [[ "$plain_ok" -eq 1 && "$strict_ok" -eq 1 && "${level_results[2]:-0}" -eq 1 ]]; then
  echo "- Overall: looks good for modern Node.js defaults."
fi

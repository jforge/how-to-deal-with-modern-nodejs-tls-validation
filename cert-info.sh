#!/usr/bin/env bash
#
# Prints PEM-encoded certificate information
#
PEM_FILE=${1:?Specify PEM-encoded certificate file}
MODE=${2:?Specify info mode (-s = short, -m = medium -l = long)}
FULL_CHAIN_CHECK=${3:-false}

function showCertificate {
  if [ $MODE == "-s" ]; then
    openssl x509 -in ${PEM_FILE} -subject -issuer -dates -noout -ext subjectAltName,nsCertType
  elif [ $MODE == "-m" ]; then
    openssl x509 -in ${PEM_FILE} -noout -text -certopt no_header,no_version,no_serial,no_signame,no_pubkey,no_sigdump,no_aux
  else
    openssl x509 -in ${PEM_FILE} -noout -text
  fi
}

function showCertificateChain {
    if [ $MODE == "-s" ]; then
      openssl crl2pkcs7 -nocrl -certfile ${PEM_FILE} | openssl pkcs7 -print_certs -noout
    else
      openssl crl2pkcs7 -nocrl -certfile ${PEM_FILE} | openssl pkcs7 -print_certs -noout -text
    fi
}

if [ "$FULL_CHAIN_CHECK" == "false" ];
then
  showCertificate
else
  showCertificateChain
fi

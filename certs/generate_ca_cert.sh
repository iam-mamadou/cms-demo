#!/bin/bash
. constants.sh

echo "Root CA private key"
openssl genrsa -aes256 \
        -out ${rootCA_key} \
        -passout ${rootCA_password} \
        2048

echo "Root CA Self-Signed Certificate..."
openssl req -x509 -new -nodes -sha256 \
        -days 365 \
        -key ${rootCA_key} \
        -passin ${rootCA_password} \
        -subj ${rootCA_subject} \
        -out ${rootCA_cert}

echo "Root CA  PFX / P12 Format..."
openssl pkcs12 -export \
        -inkey ${rootCA_key} \
        -in ${rootCA_cert} \
        -passin ${rootCA_password} \
        -passout ${rootCA_pfx_password} \
        -out ${rootCA_pfx}

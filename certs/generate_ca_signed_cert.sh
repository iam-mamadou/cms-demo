#!/bin/bash
. constants.sh

echo "Client Private key..."
openssl genrsa -aes256 \
        -passout ${client_password} \
        -out ${client_key} 2048

echo "Client CSR..."
openssl req -new -sha256 \
        -key ${client_key} \
        -passin ${client_password} \
        -subj  ${client_subject} \
        -out ${client_csr}

echo "CA Root Sign Client Certificate..."
openssl x509 -req -sha256\
        -days 365 \
        -in ${client_csr} \
        -CA ${rootCA_cert} \
        -CAkey ${rootCA_key} \
        -passin ${rootCA_password} \
        -CAcreateserial \
        -out ${client_cert}


echo "Client Cert  PFX / P12 Format..."
openssl pkcs12 -export \
        -inkey ${client_key} \
        -in ${client_cert} \
        -passin ${client_password} \
        -passout ${client_pfx_password} \
        -name ${client_name}\
        -out ${client_pfx}


#!/bin/bash

name="self_expired"
cert="${name}/${name}.crt.pem"
key="${name}/private/${name}.key.pem"
key_password="file:${name}/private/${name}.password.txt"
pfx="${name}/private/${name}.pfx"
pfx_password="file:${name}/private/${name}.pfx.password.txt"
subject="/CN=${name}"
valid_for=1
mkdir -p "${name}/private"
echo "${name}" > ${key_password/file:/}
echo "${name}" > ${pfx_password/file:/}

openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
        -days ${valid_for} \
        -passin ${key_password} \
        -subj ${subject} \
        -keyout ${key}\
        -out ${cert}

openssl pkcs12 -export \
        -inkey ${key} \
        -in ${cert} \
        -passin ${key_password} \
        -passout ${pfx_password} \
        -name ${name}\
        -out ${pfx}


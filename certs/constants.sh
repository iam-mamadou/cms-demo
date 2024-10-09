#!/bin/bash

# ROOT CA variables
rootCA_key="ca/private/rootCA.key.pem"
rootCA_password="file:ca/private/rootCA.password.txt"
rootCA_cert="ca/rootCA.crt.pem"
rootCA_subject="/CN=rootCA"
rootCA_pfx="ca/rootCA.pfx"
rootCA_pfx_password="file:ca/private/rootCA.pfx.password.txt"

# generate password files
mkdir -p ca/private/
echo "root_ca" > ${rootCA_password/file:/}
echo "root_ca" > ${rootCA_pfx_password/file:/}



# Client Variables
client_name="client"
mkdir -p "${client_name}/private/"
client_cert="${client_name}/${client_name}.crt.pem"
client_key="${client_name}/private/${client_name}.key.pem"
client_password="file:${client_name}/private/${client_name}.password.txt"
client_subject="/CN=${client_name}"
client_csr="${client_name}/private/${client_name}.csr"

client_pfx="${client_name}/private/${client_name}.pfx"
client_pfx_password="file:${client_name}/private/${client_name}.pfx.password.txt"

# generate password files
echo "root_ca" > ${client_password/file:/}
echo "root_ca" > ${client_pfx_password/file:/}

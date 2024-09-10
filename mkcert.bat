openssl req -newkey ec -pkeyopt ec_paramgen_curve:"P-256" -keyout cert-master-key.pem -out cert-att.csr -sha256 -nodes -config attestation-cert.conf

openssl x509 -req -in cert-att.csr -signkey cert-master-key.pem -out cert-att.pem -sha256 -days 3650 -extfile attestation-cert.conf -extensions v3_req

openssl x509 -in cert-att.pem -out cert-att.der -outform der
openssl ec -in cert-master-key.pem -out cert-master-key.der -outform der -conv_form uncompressed


del src\cert.c
xxd -i cert-att.der | sed -e "s/unsigned/const unsigned/g" >> src/cert.c
xxd -i cert-master-key.der | sed -e "s/unsigned/const unsigned/g" >> src/cert.c


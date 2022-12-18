mkdir certificates
rm certificates/*
echo "generate pseudo CA private key"
#openssl genrsa -out certificates/ca.key 2048
openssl ecparam -name prime256v1 -genkey -noout -out certificates/ca.key

echo "generate pseudo CA certificate signing request"
openssl req -new -sha256 -days 3650 \
        -key certificates/ca.key -out certificates/ca.csr \
        -config ./cert-conf/ca.conf

echo "generate pseudo CA certificate"
openssl x509 \
    -req \
    -days 3650 \
    -in certificates/ca.csr \
    -signkey certificates/ca.key \
    -out certificates/ca.crt

echo "generate prover private key"
openssl ecparam -genkey -name secp384r1 \
        -out certificates/prover.key

echo "generate prover certificate signing request"
openssl req -new -key certificates/prover.key \
        -out certificates/prover.csr -config \
         ./cert-conf/prover.conf

echo "CA sign prover csr"
openssl x509 \
  -req \
  -days 3650 \
  -CA certificates/ca.crt \
  -CAkey certificates/ca.key \
  -CAcreateserial \
  -in certificates/prover.csr \
  -out certificates/prover.pem\
  -extensions req_ext \
  -extfile cert-conf/prover.conf

#!/bin/sh

rm ezcrypt.yml
./ezcrypt pki init -n test -d
serial=$(./ezcrypt pki cert new --cn 'test' -o json | jq .data.serial -r)
./ezcrypt pki cert get-cert ${serial} > cert.crt
./ezcrypt pki cert chain ${serial} > chain.crt
openssl verify -verbose -CAfile chain.crt cert.crt

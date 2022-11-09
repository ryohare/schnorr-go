#!/bin/sh

PRIVATE_KEY="ECDSA"
PUBLIC_KEY="ECDSA.pub"
BITCOIN_PRIVATE_KEY="bitcoin"
BITCOIN_PUBLIC_KEY="bitcoin.pub"

echo "Generating private key"
openssl ecparam -genkey -name secp256k1 -out $PRIVATE_KEY

echo "Generating public key"
openssl ec -in $PRIVATE_KEY -pubout -out $PUBLIC_KEY

echo "Generating Bitcoin private key"
openssl ec -in $PRIVATE_KEY -outform DER|tail -c +8|head -c 32|xxd -p -c 32 > $BITCOIN_PRIVATE_KEY

echo "Generating Bitcoin public key"
openssl ec -in $PRIVATE_KEY -pubout -conv_form compressed -outform DER|tail -c 33|xxd -p -c 33 > $BITCOIN_PUBLIC_KEY
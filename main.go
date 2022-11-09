package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/decred/dcrd/crypto/blake256"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
)

func main() {

	// message to be signed is being passed in
	signPtr := flag.Bool("sign", false, "flag for signing a message")
	verifyPtr := flag.Bool("verify", false, "flag for verifying a signature")
	messagePtr := flag.String("message", "", "message to be signed")
	pubKeyPtr := flag.String("pubkey", "", "public key to verify the signature with")
	privateKeyPtr := flag.String("privkey", "", "private key to sign the message with")
	signaturePtr := flag.String("sig", "", "signature to verify")
	pubKeyFilePtr := flag.String("pubkey-file", "", "file path to a public key file")
	// privKeyFilePtr := flag.String("privkey-file", "", "file path to a public key file")
	flag.Parse()

	if *pubKeyFilePtr != "" {
		// read in the pem file
		pubkeyBytes, err := os.ReadFile(*pubKeyFilePtr)
		if err != nil {
			log.Fatalf("failed to read specified public key because %s\n", err.Error())
		}
		block, _ := pem.Decode(pubkeyBytes)
		if block == nil || block.Type != "PUBLIC KEY" {
			log.Fatal("failed to decode PEM block containing public key")
		}
		pubkeyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%T\n", pubkeyAny)
	}

	if *signPtr {

		// fmt.Printf("Signing message %s\n", *messagePtr)
		// Decode a hex-encoded private key.
		// pkBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2d4f8720ee63e502ee2869afab7de234b80c")
		pkBytes, err := hex.DecodeString(*privateKeyPtr)
		if err != nil {
			fmt.Println(err)
			return
		}
		privKey := secp256k1.PrivKeyFromBytes(pkBytes)

		// Sign a message using the private key.
		message := *messagePtr
		messageHash := blake256.Sum256([]byte(message))
		signature, err := schnorr.Sign(privKey, messageHash[:])
		if err != nil {
			fmt.Println(err)
			return
		}

		// Serialize and display the signature.
		// fmt.Printf("Serialized Signature: %x\n", signature.Serialize())
		fmt.Printf("%x\n", signature.Serialize())

		// Verify the signature for the message using the public key.
		pubKey := privKey.PubKey()
		verified := signature.Verify(messageHash[:], pubKey)

		if !verified {
			fmt.Println("signing has failed validation")
		}
	} else if *verifyPtr {
		// Decode hex-encoded serialized public key.
		pubKeyBytes, err := hex.DecodeString(*pubKeyPtr)
		if err != nil {
			fmt.Println(err)
			return
		}

		pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Decode hex-encoded serialized signature.
		sigBytes, err := hex.DecodeString(*signaturePtr)
		if err != nil {
			fmt.Println(err)
			return
		}
		signature, err := schnorr.ParseSignature(sigBytes)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Verify the signature for the message using the public key.
		message := *messagePtr
		messageHash := blake256.Sum256([]byte(message))
		verified := signature.Verify(messageHash[:], pubKey)
		fmt.Println("Signature Verified?", verified)
	} else {
		flag.PrintDefaults()
	}
}

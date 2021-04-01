package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func main() {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		log.Fatal(err)
	}

	publicKey := &privateKey.PublicKey

	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509PrivateKey,
	}

	privateKeyFile, err := os.Create("private.pem")

	if err != nil {
		log.Fatal(err)
	}

	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, privateKeyBlock)

	if err != nil {
		log.Fatal(err)
	}

	//Public Key

	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		log.Fatal(err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509PublicKey,
	}

	publicKeyFile, err := os.Create("public.pem")

	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(publicKeyFile, publicKeyBlock)

	if err != nil {
		log.Fatal(err)
	}

}

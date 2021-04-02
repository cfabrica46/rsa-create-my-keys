package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {

	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	dataPrivateKey, err := ioutil.ReadFile("private.pem")

	if err != nil {

		if os.IsNotExist(err) {
			fmt.Println(1)
			privateKey, publicKey, err = createKeys()

			if err != nil {
				log.Fatal(err)
			}

		} else {
			log.Fatal(err)
		}
	}

	dataPublicKey, err := ioutil.ReadFile("public.pem")

	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println(2)

			privateKey, publicKey, err = createKeys()

			if err != nil {
				log.Fatal(err)
			}

		} else {
			log.Fatal(err)
		}
	}

	if privateKey == nil && publicKey == nil {
		fmt.Println(3)

		privateKey, err = getPrivateKey(dataPrivateKey)

		if err != nil {
			log.Fatal(err)
		}

		publicKey, err = getPublicKey(dataPublicKey)

		if err != nil {
			log.Fatal(err)
		}

	}

	//Encriptacion

	dataOrigen, err := ioutil.ReadFile("txt.txt")

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", dataOrigen)

	dataEncriptada, err := encrypt(dataOrigen, publicKey)

	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("encrypt.enc", dataEncriptada, 0644)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", dataEncriptada)

	//activar para comprobar desencriptar encriptacion de openssl

	//	dataEncriptada, err = ioutil.ReadFile("opensll.enc")
	//
	//	if err != nil {
	//		log.Fatal(err)
	//	}

	dataDesencriptada, err := decrypt(dataEncriptada, privateKey)

	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("decrypt.txt", dataDesencriptada, 0644)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", dataDesencriptada)

}

func createKeys() (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return
	}

	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509PrivateKey,
	}

	privateKeyFile, err := os.Create("private.pem")

	if err != nil {
		return
	}

	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, privateKeyBlock)

	if err != nil {
		return
	}

	publicKey = &privateKey.PublicKey

	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)

	if err != nil {
		return
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509PublicKey,
	}

	publicKeyFile, err := os.Create("public.pem")

	if err != nil {
		return
	}

	defer publicKeyFile.Close()

	err = pem.Encode(publicKeyFile, publicKeyBlock)

	if err != nil {
		return
	}

	return
}

func getPrivateKey(dataPrivateKey []byte) (privateKey *rsa.PrivateKey, err error) {

	block, _ := pem.Decode(dataPrivateKey)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("1 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte("cfabrica46"))

		if err != nil {
			return
		}
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(b)

	if err != nil {
		return
	}

	return

}

func getPublicKey(dataPublicKey []byte) (publicKey *rsa.PublicKey, err error) {

	block, _ := pem.Decode(dataPublicKey)

	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes

	if enc {
		fmt.Println("2 is encrypted pem block")

		b, err = x509.DecryptPEMBlock(block, []byte("cfabrica46"))

		if err != nil {
			return
		}

	}

	ifc, err := x509.ParsePKIXPublicKey(b)

	if err != nil {

		log.Fatal(err)

	}

	publicKey, ok := ifc.(*rsa.PublicKey)

	if !ok {

		log.Fatal("no es llave publica")

	}

	return
}

func encrypt(dataOrigen []byte, publicKey *rsa.PublicKey) (dataEncriptada []byte, err error) {

	rng := rand.Reader

	dataEncriptada, err = rsa.EncryptPKCS1v15(rng, publicKey, dataOrigen)

	if err != nil {
		return
	}

	return
}

func decrypt(dataEncriptada []byte, privateKey *rsa.PrivateKey) (dataDesencriptada []byte, err error) {

	rng := rand.Reader

	dataDesencriptada, err = rsa.DecryptPKCS1v15(rng, privateKey, dataEncriptada)

	if err != nil {
		return
	}

	return
}

package store

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
)

type RegisterResponse struct {
	UUID string
}

type Block struct {
	SignedHash []byte
	Hash       []byte
	Messages   []string
}

func GenerateKeypair() error {
	privatekey, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		return err
	}

	publicKey := &privatekey.PublicKey

	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privatePem, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		return err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicPem, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		return err
	}

	return nil
}

func LoadPublicKeyAsString() string {
	publicKeyBytes, err := ioutil.ReadFile("public.pem")
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(publicKeyBytes)

}

func LoadClientID() string {
	var clientUUID RegisterResponse

	uuidFP, err := os.Open("uuid.json")
	if err != nil {
		return ""
	}
	defer uuidFP.Close()

	d := json.NewDecoder(uuidFP)
	err = d.Decode(&clientUUID)
	if err != nil {
		panic(err)
	}

	return clientUUID.UUID
}

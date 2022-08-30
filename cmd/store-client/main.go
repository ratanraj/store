package main

import (
	"bytes"
	"crypto"
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ratanraj/store"
)

var err error

type message struct {
	City      []string `json:"city"`
	Animal    []string `json:"animal"`
	Color     []string `json:"color"`
	FirstName []string `json:"firstname"`
	Country   []string `json:"country"`
}

var msg message

var publicKey *rsa.PublicKey
var privateKey *rsa.PrivateKey

const serverAddr = "http://server:8080"

func LoadKeys() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	// Load Public Key
	publicKeyBytes, err := ioutil.ReadFile("public.pem")
	if err != nil {
		return nil, nil, err
	}
	pubblock, _ := pem.Decode(publicKeyBytes)
	if pubblock == nil {
		return nil, nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(pubblock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	pubkey := pub.(*rsa.PublicKey)

	// Load Private Key
	privateKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		return nil, nil, err
	}
	privblock, _ := pem.Decode(privateKeyBytes)
	if privblock == nil {
		return nil, nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(privblock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return pubkey, priv, nil
}

func RegisterClient() {
	pubKeyPresent := true
	prvKeyPresent := true

	_, err = os.Stat("public.pem")
	if err != nil {
		pubKeyPresent = false
	}
	_, err = os.Stat("private.pem")
	if err != nil {
		prvKeyPresent = false
	}

	if !pubKeyPresent || !prvKeyPresent {
		store.GenerateKeypair()
	}

	publicKey, privateKey, err = LoadKeys()
	if err != nil {
		panic(err)
	}

	pubKeyBase64 := store.LoadPublicKeyAsString()

	formValues := url.Values{"public_key": {pubKeyBase64}}
	formValues["uuid"] = []string{store.LoadClientID()}

	resp, err := http.PostForm(fmt.Sprintf("%s/register", serverAddr), formValues)
	if err != nil {
		panic(err)
	}

	registerResponse := store.RegisterResponse{}

	d := json.NewDecoder(resp.Body)
	err = d.Decode(&registerResponse)
	if err != nil {
		panic(err)
	}

	if registerResponse.UUID == "" {
		panic(fmt.Errorf("failed to register client"))
	}

	fp, err := os.Create("uuid.json")
	if err != nil {
		panic(err)
	}
	defer fp.Close()

	enc := json.NewEncoder(fp)
	enc.Encode(registerResponse)
	if err != nil {
		panic(err)
	}

}

func loadMessageData() {
	fp, err := os.Open("messages.json")
	if err != nil {
		panic(err)
	}
	defer fp.Close()

	d := json.NewDecoder(fp)

	err = d.Decode(&msg)
	if err != nil {
		panic(err)
	}
}

func getRandomMessage() string {
	//['city', 'animal', 'color', 'firstname', 'country']

	seed := time.Now().Unix()

	buf, err := os.ReadFile("/etc/hostname")
	if err == nil {
		for i := range buf {
			seed += int64(buf[i])
		}
	}

	s := rand.NewSource(seed)
	r := rand.New(s)

	city := msg.City[r.Intn(len(msg.City))]
	animal := msg.Animal[r.Intn(len(msg.Animal))]
	color := msg.Color[r.Intn(len(msg.Color))]
	firstname := msg.FirstName[r.Intn(len(msg.FirstName))]
	country := msg.Country[r.Intn(len(msg.Country))]

	return strings.Join([]string{city, animal, color, firstname, country}, " ")
}

func main() {

	_, err := os.Open("uuid.json")
	if err != nil {
		RegisterClient()
	} else {
		fmt.Println("client already registered")
		publicKey, privateKey, err = LoadKeys()
		if err != nil {
			panic(err)
		}
	}

	clientUUID := store.LoadClientID()

	loadMessageData()

	for i := 0; i < 60; i++ {
		m := getRandomMessage()
		hasher := sha512.New()
		hasher.Write([]byte(m))

		signedMessage, err := rsa.SignPSS(crypto_rand.Reader, privateKey, crypto.SHA512, hasher.Sum(nil), nil)
		if err != nil {
			fmt.Println(err)
			panic(err)
		}

		buf := bytes.NewBuffer([]byte{})

		type requestBody struct {
			Message   string
			Signature string
			UUID      string
		}

		m1 := requestBody{
			Message:   m,
			Signature: base64.StdEncoding.EncodeToString(signedMessage),
			UUID:      clientUUID,
		}

		enc := json.NewEncoder(buf)
		err = enc.Encode(m1)
		if err != nil {
			panic(err)
		}

		resp, err := http.Post(fmt.Sprintf("%s/message", serverAddr), "application/json", buf)
		if err != nil {
			panic(err)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Println("failed to send one message")
		}

		time.Sleep(time.Second)
	}
}

package web

import (
	"bytes"
	"context"
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
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ratanraj/store"
)

var ctx = context.Background()
var err error

func (s *Server) Home(c *gin.Context) {

	blocks, err := s.rdb.LRange(ctx, "blocks", 0, -1).Result()
	if err != nil {
		panic(err)
	}

	decodedBlocks := []store.Block{}

	for i := range blocks {
		b, err := base64.StdEncoding.DecodeString(blocks[i])
		if err != nil {
			break
		}
		var blk store.Block
		err = json.Unmarshal(b, &blk)
		if err != nil {
			continue
		}
		decodedBlocks = append(decodedBlocks, blk)
	}

	c.JSON(http.StatusOK, gin.H{"blocks": decodedBlocks})
}

func (s *Server) Register(c *gin.Context) {
	publicKey := c.PostForm("public_key")
	clientUUID := c.PostForm("uuid")

	if clientUUID == "" {
		clientUUID = uuid.New().String()
	} else {
		fmt.Println(clientUUID)
	}

	// TODO: check if a client is already registered

	key := fmt.Sprintf("publickey~%s", clientUUID)

	err = s.rdb.Set(ctx, key, publicKey, 0).Err()
	if err != nil {
		panic(err)
	}

	c.JSON(http.StatusOK, gin.H{"uuid": clientUUID})
}

func hashAllMessages(messages []string) []byte {
	hasher := sha512.New()

	for i := range messages {
		hasher.Write([]byte(messages[i]))
	}

	return hasher.Sum(nil)
}

func signWithHash(hash []byte) ([]byte, error) {
	privateKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		return nil, err
	}
	privblock, _ := pem.Decode(privateKeyBytes)
	if privblock == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privblock.Bytes)
	if err != nil {
		return nil, err
	}

	return rsa.SignPSS(crypto_rand.Reader, privateKey, crypto.SHA512, hash, nil)
}

func (s *Server) Message(c *gin.Context) {
	d := json.NewDecoder(c.Request.Body)

	type msg1 struct {
		Message   string
		Signature string
		UUID      string
	}
	var m1 msg1

	err = d.Decode(&m1)
	if err != nil {
		panic(err)
	}

	//fmt.Println(m1.UUID, m1.Message)

	key := fmt.Sprintf("publickey~%s", m1.UUID)

	publicKeyString, err := s.rdb.Get(ctx, key).Result()
	if err != nil {
		panic(err)
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		panic(err)
	}

	pubblock, _ := pem.Decode(publicKeyBytes)
	if pubblock == nil {
		panic(fmt.Errorf("failed to parse PEM block containing the public key"))
	}
	pub, err := x509.ParsePKIXPublicKey(pubblock.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey := pub.(*rsa.PublicKey)

	// pub, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	// if err != nil {
	// 	panic(err)
	// }
	//VerifyPSS(pub *PublicKey, hash crypto.Hash, digest []byte, sig []byte, opts *PSSOptions) error

	hasher := sha512.New()
	hasher.Write([]byte(m1.Message))

	signatureBytes, err := base64.StdEncoding.DecodeString(m1.Signature)
	if err != nil {
		panic(err)
	}

	//publicKey := pub.(rsa.PublicKey)

	err = rsa.VerifyPSS(publicKey, crypto.SHA512, hasher.Sum(nil), signatureBytes, nil)
	if err != nil {
		panic(err)
	}

	key = "messagelist"

	_, err = s.rdb.RPush(ctx, key, m1.Message).Result()
	if err != nil {
		panic(err)
	}

	n, err := s.rdb.LLen(ctx, key).Result()
	if err != nil {
		panic(err)
	}
	if n < 100 {
		return
	}

	messages, err := s.rdb.LRange(ctx, key, 0, -1).Result()
	if err != nil {
		panic(err)
	}

	// 1:  Plucks the 100 messages from its queue.
	_, err = s.rdb.Del(ctx, key).Result()
	if err != nil {
		panic(err)
	}

	// 2:  Creates a hash of those messages.
	allMessageHash := hashAllMessages(messages)

	// 3:  Signs the hash.
	signature, err := signWithHash(allMessageHash)
	if err != nil {
		panic(err)
	}

	// 4:  Persists the signed hash, hash, and the 100 messages in a separate list

	block := store.Block{SignedHash: signature, Hash: allMessageHash, Messages: messages}

	buf := bytes.NewBuffer([]byte{})

	e := json.NewEncoder(buf)
	err = e.Encode(block)
	if err != nil {
		panic(err)
	}

	blockB64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	s.rdb.LPush(ctx, "blocks", blockB64)
}

// 1:  Get the number of completed blocks.
func (s *Server) GetNumberOfBlocks(c *gin.Context) {
	n, err := s.rdb.LLen(ctx, "blocks").Result()
	if err != nil {
		panic(err)
	}

	c.JSON(http.StatusOK, gin.H{"number_of_blocks": n})
}

// 2:  Get the block identified by index in the list.
func (s *Server) GetNBlock(c *gin.Context) {
	x := c.Query("n")
	n, err := strconv.ParseInt(x, 10, 64)
	if err != nil {
		n = 0
	}
	res, err := s.rdb.LIndex(ctx, "blocks", n).Result()
	if err != nil {
		panic(err)
	}
	b, err := base64.StdEncoding.DecodeString(res)
	if err != nil {
		panic(err)
	}
	var blk store.Block
	err = json.Unmarshal(b, &blk)
	if err != nil {
		panic(err)
	}

	c.JSON(http.StatusOK, gin.H{"block": blk})
}

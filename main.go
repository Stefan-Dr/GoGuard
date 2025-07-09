package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var clientPublicKeyPEM handshakeMessage

var clientPublicKey *rsa.PublicKey
var myPrivateKey *rsa.PrivateKey

type handshakeMessage struct {
	PublicKey string `json:"publicKey"`
}

func ping(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func ParseRSAPublicKeyFromPEM(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("Failed to decode PEM block containing public key!")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return rsaPublicKey, nil
}

func handshake(context *gin.Context) {
	if err := context.BindJSON(&clientPublicKeyPEM); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	clientPublicKey, err := ParseRSAPublicKeyFromPEM(clientPublicKeyPEM.PublicKey)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err})
	}

	fmt.Println(clientPublicKey)

	myPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key"})
		os.Exit(1)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&myPrivateKey.PublicKey)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate marshal public key"})
		os.Exit(1)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	context.JSON(http.StatusOK, handshakeMessage{
		PublicKey: string(publicKeyPEM),
	})
}

func main() {
	router := gin.Default()
	router.GET("/ping", ping)
	router.POST("/handshake", handshake)
	router.Run("localhost:9090")
}

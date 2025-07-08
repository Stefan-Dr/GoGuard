package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var clientPublicKey handshakeMessage

type handshakeMessage struct {
	PublicKey string `json: "publicKey"`
}

func ping(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func handshake(context *gin.Context) {
	if err := context.BindJSON(&clientPublicKey); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key"})
		os.Exit(1)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
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

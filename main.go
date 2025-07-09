package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

var clientPublicKeyPEM HandshakeMessage

var clientPublicKey *rsa.PublicKey
var myPrivateKey *rsa.PrivateKey

type HandshakeMessage struct {
	PublicKey string `json:"publicKey"`
}

type DigitalSignatureMessage struct {
	Payload   string `json:"Payload"`
	Signature string `json:"Signature"`
}

func ping(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func ParseRSAPublicKeyFromPEM(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
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

	fmt.Printf("Client public key PEM:\n%s\n", clientPublicKeyPEM.PublicKey)
	var err error
	clientPublicKey, err = ParseRSAPublicKeyFromPEM(clientPublicKeyPEM.PublicKey)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fmt.Println(clientPublicKey)

	myPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key"})
		return
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&myPrivateKey.PublicKey)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate marshal public key"})
		return
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	context.JSON(http.StatusOK, HandshakeMessage{
		PublicKey: string(publicKeyPEM),
	})
}

func digitalSignature(context *gin.Context) {

	if clientPublicKey == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "client public key not set"})
		return
	}

	var clientMessage DigitalSignatureMessage
	if err := context.BindJSON(&clientMessage); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
	}

	payload := []byte(clientMessage.Payload)
	hash := sha256.Sum256(payload)

	signatureBytes, err := base64.StdEncoding.DecodeString(clientMessage.Signature)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid base64 signature"})
		return
	}

	err = rsa.VerifyPSS(clientPublicKey, crypto.SHA256, hash[:], signatureBytes, nil)
	if err != nil {
		context.JSON(http.StatusForbidden, gin.H{"error": "invalid signature"})
		return
	}

	context.JSON(http.StatusOK, gin.H{"messagge": "Signature valid"})
}

func main() {
	router := gin.Default()
	router.GET("/ping", ping)
	router.POST("/handshake", handshake)
	router.POST("/digital-signature", digitalSignature)
	router.Run("localhost:9090")
}

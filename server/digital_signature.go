package server

import (
	"log"
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleDigitalSignature() gin.HandlerFunc {
	return func(context *gin.Context) {
		ip := context.ClientIP()
		log.Println("[ROUTE] [" + ip + "] /digital-signature")
		if s.ClientPublicKey == nil {
			log.Println("[ERROR] [" + ip + "] No public key found")
			context.JSON(http.StatusBadRequest, gin.H{"error": "client public key is missing"})
			return
		}

		var clientMessage models.DigitalSignatureMessage
		if err := context.BindJSON(&clientMessage); err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		if err := crypto.VerifySignature(clientMessage, s.ClientPublicKey); err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature"})
			return
		}

		serverResponse, err := crypto.SendSignature(s.MyPrivateKey)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		context.JSON(http.StatusOK, serverResponse)
		log.Println("[INFO] [" + ip + "] Signature sent")
	}
}

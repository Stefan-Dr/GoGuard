package server

import (
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleDigitalSignature() gin.HandlerFunc {
	return func(context *gin.Context) {
		if s.ClientPublicKey == nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "client public key is missing"})
		}

		var clientMessage models.DigitalSignatureMessage
		if err := context.BindJSON(&clientMessage); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		if err := crypto.VerifySignature(clientMessage, s.ClientPublicKey); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature"})
			return
		}

		serverResponse, err := crypto.SendSignature(s.MyPrivateKey)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		}

		context.JSON(http.StatusOK, serverResponse)
	}
}

package server

import (
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleHandshake() gin.HandlerFunc {
	return func(context *gin.Context) {
		var msg models.HandshakeMessage
		if err := context.BindJSON(&msg); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		var err error
		s.ClientPublicKey, err = crypto.ParseRSAPublicKeyFromPEM(msg.PublicKey)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		s.MyPrivateKey, err = crypto.GeneratePrivateKey()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		publicKeyPEM, err := crypto.MakePublicKeyPEM(s.MyPrivateKey)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		context.JSON(http.StatusOK, models.HandshakeMessage{
			PublicKey: string(publicKeyPEM),
		})
	}
}

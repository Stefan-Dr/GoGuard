package server

import (
	"fmt"
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleLicence() gin.HandlerFunc {
	return func(context *gin.Context) {
		var msg models.LicenceMessage
		if err := context.BindJSON(&msg); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		uid, err := crypto.AESDecrypt(msg.Uid, s.GCM)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}

		fmt.Print(uid)
	}
}

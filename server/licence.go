package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/db"
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

		licence := sha256.Sum256([]byte(uid))
		licenceString := base64.StdEncoding.EncodeToString(licence[:])

		result, err := db.AddLicence(s.db, licenceString, uid)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(result)

	}
}

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
			return
		}

		licence := sha256.Sum256([]byte(uid))
		licenceString := base64.StdEncoding.EncodeToString(licence[:])

		result, err := db.AddLicence(s.db, licenceString, uid)
		if err != nil || result == 0 {
			fmt.Println(err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		licenceEncrypted, err := crypto.AESEncrypt(licence[:], s.CipherBlock, s.GCM)
		if err != nil {
			if err != nil {
				context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			}
		}
		context.JSON(http.StatusOK, gin.H{"licence": licenceEncrypted})
	}
}

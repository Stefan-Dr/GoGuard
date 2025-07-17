package server

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/db"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleLicence() gin.HandlerFunc {
	return func(context *gin.Context) {
		var msg models.LicenceRequestMessage
		if err := context.BindJSON(&msg); err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		hwid, err := crypto.AESDecrypt(msg.Hwid, s.GCM)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid Hwid"})
			return
		}

		device, err := db.GetDeviceByHwid(s.db, hwid)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid Hwid " + err.Error()})
			return
		}

		if device.Uid.Valid {
			licence, err := base64.StdEncoding.DecodeString(strings.TrimSpace(device.LicenceKey.String))
			if err != nil {
				fmt.Println(err.Error() + "; DecodeString for device.LicenceKey")
				context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return
			}

			licenceEncrypted, err := crypto.AESEncrypt(licence[:], s.CipherBlock, s.GCM)
			if err != nil {
				fmt.Println(err.Error() + "; AESEncrypt for licence")
				context.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
				return
			}

			context.JSON(http.StatusOK, gin.H{"licence": licenceEncrypted})
			return
		}

		uid, err := crypto.MakeUid(hwid, s.ServerKey)
		if err != nil {
			fmt.Println(err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		licence := sha256.Sum256([]byte(uid))
		licenceString := base64.StdEncoding.EncodeToString(licence[:])

		result, err := db.AddLicence(s.db, hwid, licenceString, uid)
		if err != nil || result == 0 {
			fmt.Println(err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		licenceEncrypted, err := crypto.AESEncrypt(licence[:], s.CipherBlock, s.GCM)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
			return
		}
		context.JSON(http.StatusOK, gin.H{"licence": licenceEncrypted})
	}
}

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/db"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleLicence() gin.HandlerFunc {
	return func(context *gin.Context) {
		ip := context.ClientIP()
		log.Println("[ROUTE] [" + ip + "] /licence")

		sessionIdString := context.GetHeader("Session-ID")

		s.mutex.RLock()
		session, sessionExists := s.sessions[sessionIdString]
		var expiredSession bool
		if sessionExists {
			expiredSession = s.sessions[sessionIdString].IsExpired()
		}
		s.mutex.RUnlock()

		if !sessionExists || expiredSession {
			log.Println("[ERROR] [" + ip + "] Invalid or expired session")
			context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
			if expiredSession {
				s.mutex.Lock()
				delete(s.sessions, sessionIdString)
				s.mutex.Unlock()
			}
			return
		}

		var msg models.LicenceRequestMessage
		if err := context.BindJSON(&msg); err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		hwid, err := crypto.AESDecrypt(msg.Hwid, session.GCM)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid Hwid"})
			return
		}

		device, err := db.GetDeviceByHwid(s.db, hwid)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid Hwid "})
			return
		}

		if device.Uid.Valid {
			uid, err := crypto.MakeUid(hwid, s.ServerKey)
			if err != nil {
				log.Println("[ERROR] [" + ip + "] " + err.Error())
				context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return
			}
			if device.Uid.String != uid {
				log.Println("[ERROR] [" + ip + "]  hwid : " + hwid)
				context.JSON(http.StatusInternalServerError, gin.H{"error": "access denied"})
			}
			licence, err := base64.StdEncoding.DecodeString(strings.TrimSpace(device.LicenceKey.String))
			if err != nil {
				log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
				context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
				return
			}

			licenceEncrypted, err := crypto.AESEncrypt(licence[:], session.CipherBlock, session.GCM)
			if err != nil {
				log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
				context.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
				return
			}

			context.JSON(http.StatusOK, gin.H{"licence": licenceEncrypted})
			log.Println("[INFO] [" + ip + "] " + "Licence sent for device with hwid : " + hwid)
			return
		}

		uid, err := crypto.MakeUid(hwid, s.ServerKey)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		licence := sha256.Sum256([]byte(uid))
		licenceString := base64.StdEncoding.EncodeToString(licence[:])

		result, err := db.AddLicence(s.db, hwid, licenceString, uid)
		if err != nil || result == 0 {
			log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		licenceEncrypted, err := crypto.AESEncrypt(licence[:], session.CipherBlock, session.GCM)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error() + " hwid : " + hwid)
			context.JSON(http.StatusBadRequest, gin.H{"error": "internal server error"})
			return
		}
		context.JSON(http.StatusOK, gin.H{"licence": licenceEncrypted})
		log.Println("[INFO] [" + ip + "] " + "Licence created and sent for device with hwid : " + hwid)

		s.mutex.Lock()
		delete(s.sessions, sessionIdString)
		s.mutex.Unlock()
	}
}

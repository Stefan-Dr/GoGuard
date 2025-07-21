package server

import (
	"log"
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/gin-gonic/gin"
)

// The data we want to encrypt needs to be in []byte because AES required binary data

func (s *Server) HandleAESKey() gin.HandlerFunc {
	return func(context *gin.Context) {
		ip := context.ClientIP()
		log.Println("[ROUTE] [" + ip + "] /get-key")

		var sessionIdString = context.GetHeader("Session-ID")
		s.mutex.RLock()
		session, sessionExists := s.sessions[sessionIdString]
		var expiredSession bool
		if sessionExists {
			expiredSession = s.sessions[sessionIdString].IsExpired()
		}
		s.mutex.RUnlock()

		if !sessionExists || expiredSession {
			log.Println("[ERROR] [" + ip + "] invalid or expired session")
			context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
			if expiredSession {
				s.mutex.Lock()
				delete(s.sessions, sessionIdString)
				s.mutex.Unlock()
			}
			return
		}

		if session.ClientPublicKey == nil {
			log.Println("[ERROR] [" + ip + "] Missing public key")
			context.JSON(http.StatusBadRequest, gin.H{"Error": "missing public key"})
			return
		}

		var err error
		s.mutex.Lock()
		session.Key, err = crypto.GenerateAESKey()
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			s.mutex.Unlock()
			return
		}

		session.CipherBlock, err = crypto.GenerateCipherBlock(session.Key)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			s.mutex.Unlock()
			return
		}

		session.GCM, err = crypto.GenerateGCM(session.CipherBlock)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			s.mutex.Unlock()
			return
		}
		s.mutex.Unlock()

		encryptedKey, err := crypto.Encrypt(session.Key, session.ClientPublicKey)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			return
		}

		context.JSON(http.StatusOK, gin.H{"key": encryptedKey})
		log.Println("[INFO] [" + ip + "] AES256 key sent")
	}
}

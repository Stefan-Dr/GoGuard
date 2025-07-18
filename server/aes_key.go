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
		if s.sessions[sessionIdString] == nil {
			log.Println("[ERROR] [" + ip + "] No session id in header")
			context.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired session"})
			s.mutex.RUnlock()
			return
		}
		session := s.sessions[sessionIdString]
		s.mutex.RUnlock()

		if session.ClientPublicKey == nil {
			log.Println("[ERROR] [" + ip + "] Missing public key")
			context.JSON(http.StatusBadRequest, gin.H{"Error": "missing public keyt"})
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

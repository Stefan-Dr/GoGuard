package server

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/Stefan-Dr/GoGuard/models"
	"github.com/gin-gonic/gin"
)

func (s *Server) HandleHandshake() gin.HandlerFunc {
	return func(context *gin.Context) {
		ip := context.ClientIP()
		log.Println("[ROUTE] [" + ip + "] /hanshake")
		var msg models.HandshakeMessage
		if err := context.BindJSON(&msg); err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON"})
			return
		}

		sessionId := make([]byte, 32)
		_, erro := io.ReadFull(rand.Reader, sessionId)
		if erro != nil {
			log.Println("[ERROR] [" + ip + "] " + erro.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		sessionIdString := base64.RawURLEncoding.EncodeToString(sessionId)

		var err error
		session := &Session{}

		session.ClientPublicKey, err = crypto.ParseRSAPublicKeyFromPEM(msg.PublicKey)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		session.MyPrivateKey, err = crypto.GeneratePrivateKey()
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		publicKeyPEM, err := crypto.MakePublicKeyPEM(session.MyPrivateKey)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		s.mutex.Lock()
		s.sessions[sessionIdString] = session
		s.mutex.Unlock()

		context.JSON(http.StatusOK, gin.H{
			"publicKey":  string(publicKeyPEM),
			"Session-ID": sessionIdString,
		})

		log.Println("[INFO] [" + ip + "]  Sending server public key and Session-ID")
	}
}

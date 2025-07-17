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
		if s.ClientPublicKey == nil {
			log.Println("[ERROR] [" + ip + "] Missing public key")
			context.JSON(http.StatusBadRequest, gin.H{"Error": "missing public keyt"})
			return
		}

		var err error
		s.Key, err = crypto.GenerateAESKey()
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			return
		}

		s.CipherBlock, err = crypto.GenerateCipherBlock(s.Key)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			return
		}

		s.GCM, err = crypto.GenerateGCM(s.CipherBlock)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			return
		}

		encryptedKey, err := crypto.Encrypt(s.Key, s.ClientPublicKey)
		if err != nil {
			log.Println("[ERROR] [" + ip + "] " + err.Error())
			context.JSON(http.StatusInternalServerError, gin.H{"Error": "internal server error"})
			return
		}

		context.JSON(http.StatusOK, gin.H{"key": encryptedKey})
		log.Println("[INFO] [" + ip + "] AES256 key sent")
	}
}

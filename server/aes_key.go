package server

import (
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/gin-gonic/gin"
)

// The data we want to encrypt needs to be in []byte because AES required binary data

func (s *Server) HandleAESKey() gin.HandlerFunc {
	return func(context *gin.Context) {
		if s.ClientPublicKey == nil {
			context.JSON(http.StatusBadRequest, gin.H{"Error": "Server doesn't have your public key yet"})
			return
		}

		var err error
		s.Key, err = crypto.GenerateAESKey()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}

		s.CipherBlock, err = crypto.GenerateCipherBlock(s.Key)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}

		s.GCM, err = crypto.GenerateGCM(s.CipherBlock)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}

		encryptedKey, err := crypto.Encrypt(s.Key, s.ClientPublicKey)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}

		context.JSON(http.StatusOK, gin.H{"key": encryptedKey})
	}
}

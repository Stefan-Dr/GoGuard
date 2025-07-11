package server

import (
	"net/http"

	"github.com/Stefan-Dr/GoGuard/crypto"
	"github.com/gin-gonic/gin"
)

// The data we want to encrypt needs to be in []byte because AES required binary data

func (s *Server) HandleAESKey() gin.HandlerFunc {
	return func(context *gin.Context) {
		var err error
		s.Key, err = crypto.GenerateAESKey()
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}

		s.CipherBlock, err = crypto.GenerateCypherBlock(s.Key)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}

		s.GCM, err = crypto.GenerateGCM(s.CipherBlock)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
			return
		}
	}
}

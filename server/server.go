package server

import (
	"crypto/cipher"
	"crypto/rsa"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Server struct {
	router          *gin.Engine
	ClientPublicKey *rsa.PublicKey
	MyPrivateKey    *rsa.PrivateKey
	Key             []byte
	CipherBlock     cipher.Block
	GCM             cipher.AEAD
}

func NewServer() *Server {
	s := &Server{
		router: gin.Default(),
	}

	return s
}

func (s *Server) RegisterRoutes() {
	s.router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	s.router.POST("/handshake", s.HandleHandshake())
	s.router.POST("/digital-signature", s.HandleDigitalSignature())
	s.router.GET("/get-key", s.HandleAESKey())
	s.router.POST("/create-licence", s.HandleLicence())
}

func (s *Server) Start() {
	s.router.Run("localhost:9090")
}

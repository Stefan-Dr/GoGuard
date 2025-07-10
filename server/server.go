package server

import (
	"crypto/rsa"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Server struct {
	router          *gin.Engine
	ClientPublicKey *rsa.PublicKey
	MyPrivateKey    *rsa.PrivateKey
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
	s.router.POST("/digital-signature", s.DigitalSignature())
}

func (s *Server) Start() {
	s.router.Run("localhost:9090")
}

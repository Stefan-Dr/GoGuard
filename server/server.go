package server

import (
	"crypto/cipher"
	"crypto/rsa"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Server struct {
	router          *gin.Engine
	db              *sql.DB
	ClientPublicKey *rsa.PublicKey
	MyPrivateKey    *rsa.PrivateKey
	Key             []byte
	CipherBlock     cipher.Block
	GCM             cipher.AEAD
}

func NewServer(database *sql.DB) *Server {
	s := &Server{
		router: gin.Default(),
		db:     database,
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

func (s *Server) Start(addr string) {
	s.router.Run(addr)
}

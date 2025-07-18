package server

import (
	"crypto/cipher"
	"crypto/rsa"
	"database/sql"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type Session struct {
	ClientPublicKey *rsa.PublicKey
	MyPrivateKey    *rsa.PrivateKey
	Key             []byte
	CipherBlock     cipher.Block
	GCM             cipher.AEAD
	ExpiresAt       time.Time
}

type Server struct {
	router    *gin.Engine
	db        *sql.DB
	sessions  map[string]*Session
	mutex     sync.RWMutex
	ServerKey string
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func NewServer(database *sql.DB, key string) *Server {
	s := &Server{
		router:    gin.Default(),
		db:        database,
		ServerKey: key,
		sessions:  make(map[string]*Session),
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
	s.router.POST("/licence", s.HandleLicence())
}

func (s *Server) Start(addr string) {
	s.router.Run(addr)
}

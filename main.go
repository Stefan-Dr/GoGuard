package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func ping(context *gin.Context) {
	context.JSON(http.StatusOK, gin.H{"message": "pong"})
}

func main() {
	router := gin.Default()
	router.GET("/ping", ping)
	router.Run("localhost:9090")
}

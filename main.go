package main

import (
	"github.com/Stefan-Dr/GoGuard/server"
)

func main() {
	srv := server.NewServer()
	srv.RegisterRoutes()
	srv.Start()
}

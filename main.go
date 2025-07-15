package main

import (
	"github.com/Stefan-Dr/GoGuard/server"
)

func main() {
	var cfg server.Config
	cfg.LoadConfig()

	srv := server.NewServer()
	srv.RegisterRoutes()
	srv.Start(cfg.API.Address)
}

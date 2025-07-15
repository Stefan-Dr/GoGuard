package main

import (
	"fmt"

	"github.com/Stefan-Dr/GoGuard/db"
	"github.com/Stefan-Dr/GoGuard/server"
)

func main() {
	var cfg server.Config
	cfg.LoadConfig()

	_, err := db.ConnectDB(cfg.Database.Username, cfg.Database.Password, cfg.Database.ServerName, cfg.Database.Database)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	srv := server.NewServer()
	srv.RegisterRoutes()
	srv.Start(cfg.API.Address)
}

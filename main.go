package main

import (
	"log"
	"os"

	"github.com/Stefan-Dr/GoGuard/db"
	"github.com/Stefan-Dr/GoGuard/server"
)

func main() {
	// open log file
	logFile, err := os.OpenFile("GoGuardLog.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Panic(err)
	}
	defer logFile.Close()

	log.SetOutput(logFile)

	log.SetFlags(log.Lshortfile | log.LstdFlags)

	var cfg server.Config
	cfg.LoadConfig()

	db, err := db.ConnectDB(cfg.Database.Username, cfg.Database.Password, cfg.Database.ServerName, cfg.Database.Database)
	if err != nil {
		log.Panic("[ERROR] " + err.Error())
		return
	}

	srv := server.NewServer(db, cfg.ServerKey)
	srv.RegisterRoutes()
	srv.Start(cfg.API.Address)
}

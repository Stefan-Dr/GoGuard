package server

import (
	"encoding/json"
	"io"
	"log"
	"os"
)

type Config struct {
	Database struct {
		ServerName string `json:"servername"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Database   string `json:"database"`
		Table      string `json:"table"`
	} `json:"database"`

	API struct {
		Address string `json:"address"`
	} `json:"API"`

	ServerKey string `json:"serverkey"`
}

func (c *Config) LoadConfig() {
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Println("[ERROR] " + err.Error())
	}

	byteValue, _ := io.ReadAll(configFile)

	json.Unmarshal(byteValue, &c)
	log.Println("[INFO] Config loaded")
}

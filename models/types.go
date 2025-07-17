package models

import "database/sql"

type HandshakeMessage struct {
	PublicKey string `json:"publicKey"`
}

type DigitalSignatureMessage struct {
	Payload   string `json:"Payload"`
	Signature string `json:"Signature"`
}

type LicenceRequestMessage struct {
	Hwid string `json:"Hwid"`
}

type Device struct {
	Id         int64
	Hwid       string
	Uid        sql.NullString
	LicenceKey sql.NullString
	DateTime   sql.NullTime
}

package models

type HandshakeMessage struct {
	PublicKey string `json:"publicKey"`
}

type DigitalSignatureMessage struct {
	Payload   string `json:"Payload"`
	Signature string `json:"Signature"`
}

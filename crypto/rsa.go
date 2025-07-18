package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/Stefan-Dr/GoGuard/models"
)

func ParseRSAPublicKeyFromPEM(pemString string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := pubKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return rsaPublicKey, nil
}

func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func MakePublicKeyPEM(pvtKey *rsa.PrivateKey) ([]byte, error) {
	if pvtKey == nil {
		return nil, errors.New("can't make a PublicKeyPEM from nil")
	}
	pubKeyByte, err := x509.MarshalPKIXPublicKey(&pvtKey.PublicKey)
	if err != nil {
		return nil, err
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyByte,
	})

	return pubKeyPEM, nil
}

func VerifySignature(clientMessage models.DigitalSignatureMessage, pubKey *rsa.PublicKey) error {
	payload := []byte(clientMessage.Payload)
	hash := sha256.Sum256(payload)
	var signatureBytes []byte
	var err error

	signatureBytes, err = base64.StdEncoding.DecodeString(clientMessage.Signature)
	if err != nil {
		return err
	}

	err = rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], signatureBytes, nil)

	return err
}

func SendSignature(privKey *rsa.PrivateKey) (*models.DigitalSignatureMessage, error) {
	payload := []byte("hello, world")

	hash := sha256.Sum256(payload)

	signatureRaw, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, err
	}

	signature := base64.StdEncoding.EncodeToString(signatureRaw)
	return &models.DigitalSignatureMessage{
		Payload:   string(payload),
		Signature: signature,
	}, nil
}

func Encrypt(data []byte, pubKey *rsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", errors.New("can't encrypt with nil as publicKey")
	}
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, data, nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

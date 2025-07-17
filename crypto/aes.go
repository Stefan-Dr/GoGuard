package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	var err error
	_, err = rand.Reader.Read(key)

	return key, err
}

func GenerateCipherBlock(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)

	return block, err
}

func GenerateGCM(block cipher.Block) (cipher.AEAD, error) {
	if block == nil {
		return nil, errors.New("cipher block is nil")
	}
	gcm, err := cipher.NewGCM(block)

	return gcm, err
}

func AESDecrypt(msg string, gcm cipher.AEAD) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(msg)
	if err != nil {
		fmt.Println("decoding string failed")
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println("encrypted message can't be shorter than nonce")
		return "", errors.New("encrypted message can't be shorter than nonce")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println("gcm.Open failed")
		return "", err
	}

	return string(plaintext), nil
}

func AESEncrypt(licence []byte, block cipher.Block, gcm cipher.AEAD) (string, error) {
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, licence, nil)
	text := base64.StdEncoding.EncodeToString(ciphertext)

	return text, nil
}

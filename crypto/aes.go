package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
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

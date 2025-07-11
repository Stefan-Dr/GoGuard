package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	var err error
	_, err = rand.Reader.Read(key)

	return key, err
}

func GenerateCypherBlock(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)

	return block, err
}

func GenerateGCM(block cipher.Block) (cipher.AEAD, error) {
	gcm, err := cipher.NewGCM(block)

	return gcm, err
}

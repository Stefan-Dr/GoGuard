package crypto

import (
	"crypto/sha256"
	"encoding/base64"
)

func MakeUid(hwid string, key string) (string, error) {
	root := key + hwid + key
	rootBytes := []byte(root)

	uid := sha256.Sum256(rootBytes)
	return base64.StdEncoding.EncodeToString(uid[:]), nil
}

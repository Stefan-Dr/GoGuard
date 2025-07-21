package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

func MakeUid(hwid string, key string) (string, error) {
	if hwid == "" {
		return "", errors.New("invalid hwid, empty string")
	}
	if key == "" {
		return "", errors.New("invalid serve key, empty string")
	}

	root := key + hwid + key
	rootBytes := []byte(root)

	uid := sha256.Sum256(rootBytes)
	return base64.StdEncoding.EncodeToString(uid[:]), nil
}

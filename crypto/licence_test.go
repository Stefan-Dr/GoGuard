package crypto

import (
	"testing"
)

func TestMakeUid(t *testing.T) {
	_, err := MakeUid("", "")
	if err == nil {
		t.Errorf("should return an error when trying to make a UID, when given an empty string as hwid or an empty server key, but got nil")
	}
}

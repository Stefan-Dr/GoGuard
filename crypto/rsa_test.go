package crypto

import (
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	pvtKey1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error  when creating privateKey , got %v", err)
	}

	pvtKey2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error  when creating privateKey , got %v", err)
	}

	if pvtKey1 == pvtKey2 {
		t.Errorf("Expected different keys on subsequent calls, got identical keys")
	}
}

func TestMakePublicKeyPEM(t *testing.T) {
	pvtKey1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error when creating privateKey , got %v", err)
	}

	_, err = MakePublicKeyPEM(pvtKey1)
	if err != nil {
		t.Fatalf("Expected no error when creating publicKeyPEM from a succesfully generated privateKey , got %v", err)
	}

	_, err = MakePublicKeyPEM(nil)
	if err == nil {
		t.Errorf("Expected error when making PublicKeyPEM from nil, but got no error")
	}
}

func TestParseRSAPublicKeyFromPEM(t *testing.T) {
	pvtKey1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error when creating privateKey , got %v", err)
	}

	publicKeyPEM, err := MakePublicKeyPEM(pvtKey1)
	if err != nil {
		t.Fatalf("Expected no error when creating publicKeyPEM from a succesfully generated privateKey , got %v", err)
	}

	pubKey, err := ParseRSAPublicKeyFromPEM(string(publicKeyPEM))
	if err != nil {
		t.Fatalf("Expected no error when getting publicKey from PublicKeyPEM , got %v", err)
	}

	pubKey1 := &pvtKey1.PublicKey

	if pubKey != pubKey1 {
		t.Errorf("Expected to get the same publicKey when applying MakePublicKeyPEM then ParseRSAPublicKeyFromPEM")
	}
}

func TestEncrypt(t *testing.T) {
	pvtKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error when creating privateKey , got %v", err)
	}

	aesKey, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Expected no error when getting publicKey from PublicKeyPEM , got %v", err)
	}

	_, err = Encrypt(aesKey, nil)
	if err == nil {
		t.Errorf("Expected error when encrypting AES256 key with nil as publicKey , but got no error")
	}

	_, err = Encrypt(aesKey, &pvtKey.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error when encypting AES256 key with valid publicKey , got %v", err)
	}
}

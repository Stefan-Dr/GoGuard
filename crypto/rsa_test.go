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

	// For RSA public keys, the only meaningful fields are N (the modulus, *big.Int) and E (the exponent, int).
	// These fields uniquely define the key, so equality should be checked by comparing them, not by comparing pointers!
	if pubKey.N.Cmp(pubKey1.N) != 0 || pubKey.E != pubKey1.E {
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

	_, err = Encrypt(nil, nil)
	if err == nil {
		t.Errorf("Expected error when encrypting nil key with nil as publicKey , but got no error")
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

func TestMakeSignature(t *testing.T) {
	_, err := MakeSignature(nil)
	if err == nil {
		t.Errorf("Expected an error when trying to sign string with nil, but got no error")
	}

	pvtKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error when creating privateKey , got %v", err)
	}

	_, err = MakeSignature(pvtKey)
	if err != nil {
		t.Errorf("Expected no error when trying to sign a string with a privateKey, but got %v", err)
	}
}

func TestVerifySignature(t *testing.T) {
	pvtKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Expected no error when creating privateKey , got %v", err)
	}

	signedMsg, err := MakeSignature(pvtKey)
	if err != nil {
		t.Errorf("Expected no error when trying to sign a string with a privateKey, but got %v", err)
	}

	err = VerifySignature(*signedMsg, nil)
	if err == nil {
		t.Errorf("Expected no error when verifying a message with nil as privateKey , but got no error")
	}

	err = VerifySignature(*signedMsg, &pvtKey.PublicKey)
	if err != nil {
		t.Errorf("Expected no error when trying to verify a signature with the same private/public key pair, but got %v", err)
	}
}

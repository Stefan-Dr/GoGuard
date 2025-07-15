package crypto

import (
	"crypto/cipher"
	"testing"
)

func TestGenerateAESKey(t *testing.T) {
	key1, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(key1) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key1))
	}

	key2, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Expected no error on second call, got %v", err)
	}

	if len(key2) != 32 {
		t.Errorf("Expected key length 32 on second call, got %d", len(key2))
	}

	// Are keys different check (probability for them being same is insanely small)
	if string(key1) == string(key2) {
		t.Errorf("Expected different keys on subsequent calls, got identical keys")
	}
}

func TestGenerateCipherBlock(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	_, err = GenerateCipherBlock(key)
	if err != nil {
		t.Fatalf("Failed to generate cipher block with valid key %v", err)
	}
}

func TestGenerateCipherBlock_EdgeCases(t *testing.T) {
	// Key length 0 (nil)
	_, err := GenerateCipherBlock(nil)
	if err == nil {
		t.Errorf("Expected error for nil key, got nil")
	}

	// Key length 10 (invalid length)
	_, err = GenerateCipherBlock(make([]byte, 10))
	if err == nil {
		t.Errorf("Expected error for invalid key length 10, got nil")
	}

	// Key length 15 (invalid length)
	_, err = GenerateCipherBlock(make([]byte, 15))
	if err == nil {
		t.Errorf("Expected error for invalid key length 15, got nil")
	}
}

func TestGenerateGCM(t *testing.T) {
	key, err := GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	block, err := GenerateCipherBlock(key)
	if err != nil {
		t.Fatalf("Failed to generate cipher block with valid key %v", err)
	}

	_, err = GenerateGCM(block)
	if err != nil {
		t.Fatalf("Failed to generate gcm with valid cipher block %v", err)
	}
}

func TestGenerateGCM_EdgeCases(t *testing.T) {
	var block cipher.Block = nil
	_, err := GenerateGCM(block)
	if err == nil {
		t.Errorf("Expected error when passing nil cipher block, got nil")
	}
}

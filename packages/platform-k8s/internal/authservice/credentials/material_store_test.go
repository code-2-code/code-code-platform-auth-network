package credentials

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestAESGCMCredentialMaterialEncryptorRoundTrip(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{7}, 32)
	encryptor, err := NewAESGCMCredentialMaterialEncryptor("local-v1", key)
	if err != nil {
		t.Fatalf("NewAESGCMCredentialMaterialEncryptor() error = %v", err)
	}

	encrypted, err := encryptor.Encrypt([]byte("secret-value"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if encrypted.KeyID != "local-v1" {
		t.Fatalf("key id = %q, want local-v1", encrypted.KeyID)
	}
	if bytes.Contains(encrypted.Ciphertext, []byte("secret-value")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plaintext, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if got, want := string(plaintext), "secret-value"; got != want {
		t.Fatalf("plaintext = %q, want %q", got, want)
	}
}

func TestAESGCMCredentialMaterialEncryptorFromBase64(t *testing.T) {
	t.Parallel()

	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	if _, err := NewAESGCMCredentialMaterialEncryptorFromBase64("local-v1", key); err != nil {
		t.Fatalf("NewAESGCMCredentialMaterialEncryptorFromBase64() error = %v", err)
	}
}

package crypter

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestAesCrypter(t *testing.T) {
	key := make([]byte, AES256KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	ac := NewAesCrypter(key)
	plainText := []byte("hello world")
	desiredLen := ac.LenAfterEncrypted(len(plainText))
	cipher := make([]byte, desiredLen)
	ac.Encrypt(cipher, plainText)
	if cap(cipher) > desiredLen {
		t.Errorf("cipher len larger than desired value (%d > %d)", cap(cipher), desiredLen)
	}
	decrypted := make([]byte, len(plainText))
	ac.Decrypt(decrypted, cipher)
	if !bytes.Equal(decrypted, plainText) {
		t.Error("decrypted != plaintext")
	}
}

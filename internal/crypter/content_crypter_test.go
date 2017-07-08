package crypter

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestCryptBlock(t *testing.T) {
	key := make([]byte, AES256KeySize)
	fileID := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, fileID); err != nil {
		panic(err)
	}
	ac := NewAesCrypter(key)
	cc := NewContentCrypter(ac, 1024)
	plainText := []byte("hello world")
	desiredLen := ac.LenAfterEncrypted(len(plainText)) + signLen
	cipher := cc.encryptBlock(plainText, 0, fileID)
	if len(cipher) > desiredLen {
		t.Errorf("cipher len larger than desired value (%d > %d)", cap(cipher), desiredLen)
	}
	decrypted, err := cc.decryptBlock(cipher, 0, fileID)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Error("decrypted != plaintext")
	}
}

package corecrypter

import (
	"bytes"
	"fmt"
	"testing"
)

func TestAesCrypter(t *testing.T) {
	testAesCrypter(10, t)
	testAesCrypter(1024, t)
}

func TestDesCrypter(t *testing.T) {
	testDesCrypter(10, t)
	testDesCrypter(1024, t)
}

func testAesCrypter(plainLen int, t *testing.T) {
	key, err := RandomKey(AES256)
	if err != nil {
		panic(err)
	}
	ac := NewAesCrypter(key)
	plainText := RandBytes(plainLen)
	desiredLen := ac.LenAfterEncrypted(len(plainText))
	cipher := make([]byte, desiredLen)
	ac.Encrypt(cipher, plainText)
	if cap(cipher) > desiredLen {
		t.Errorf("cipher len larger than desired value (%d > %d)", cap(cipher), desiredLen)
	}
	decrypted := make([]byte, len(plainText))
	ac.Decrypt(decrypted, cipher)
	if !bytes.Equal(decrypted, plainText) {
		fmt.Println(plainText)
		fmt.Println(decrypted)
		t.Error("decrypted != plaintext")
	}
}

func testDesCrypter(plainLen int, t *testing.T) {
	key, err := RandomKey(DES)
	if err != nil {
		panic(err)
	}
	ac := NewDesCrypter(key)
	plainText := RandBytes(plainLen)
	desiredLen := ac.LenAfterEncrypted(len(plainText))
	cipher := make([]byte, desiredLen)
	ac.Encrypt(cipher, plainText)
	if cap(cipher) > desiredLen {
		t.Errorf("cipher len larger than desired value (%d > %d)", cap(cipher), desiredLen)
	}
	decrypted := make([]byte, len(plainText))
	ac.Decrypt(decrypted, cipher)
	if !bytes.Equal(decrypted, plainText) {
		fmt.Println(plainText)
		fmt.Println(decrypted)
		t.Error("decrypted != plaintext")
	}
}

package contcrypter

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/declan94/cfcryptfs/corecrypter"
)

var key = make([]byte, corecrypter.AES256KeySize)
var fileID = make([]byte, 32)

func getCC(plainBS int) (*ContentCrypter, corecrypter.CoreCrypter) {
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(rand.Reader, fileID); err != nil {
		panic(err)
	}
	ac := corecrypter.NewAesCrypter(key)
	cc := NewContentCrypter(ac, plainBS)
	return cc, ac
}

func TestCryptBlock(t *testing.T) {
	cc, ac := getCC(1024)
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

func TestCryptBlocks(t *testing.T) {
	plainBS := 256
	cc, _ := getCC(plainBS)
	plainText := make([]byte, int(plainBS*5+plainBS/2))
	if _, err := io.ReadFull(rand.Reader, plainText); err != nil {
		panic(err)
	}
	blocks := make([][]byte, 6)
	for i := 0; i < 5; i++ {
		blocks[i] = plainText[i*plainBS : (i+1)*plainBS]
	}
	blocks[5] = plainText[5*plainBS:]
	cipher := cc.EncryptBlocks(blocks, 0, fileID)
	decrypted, err := cc.DecryptBlocks(cipher, 0, fileID)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(decrypted, plainText) {
		t.Error("decrypted != plaintext")
	}
}

func TestPartial(t *testing.T) {
	plainBS := 256
	cc, _ := getCC(plainBS)
	intraBlocks := cc.ExplodePlainRange(uint64(plainBS/2), plainBS*5)
	for i, blk := range intraBlocks {
		if i == 0 {
			if blk.Skip != int(plainBS/2) {
				t.Error("First block skip error")
			}
			if blk.Length != int(plainBS/2) {
				t.Error("First block length error")
			}
			if !blk.Partial {
				t.Error("First block partial error")
			}
		} else if i == len(intraBlocks)-1 {
			if blk.Skip != 0 {
				t.Error("Last block skip error")
			}
			if blk.Length != int(plainBS/2) {
				t.Error("Last block length error")
			}
			if !blk.Partial {
				t.Error("Last block partial error")
			}
		} else {
			if blk.Skip != 0 {
				t.Error("Middle block skip error")
			}
			if blk.Length != plainBS {
				t.Error("Middle block length error")
			}
			if blk.Partial {
				t.Error("Middle block partial error")
			}
		}
	}
}

package crypter

// CoreCrypter defines interface for core crypt module
type CoreCrypter interface {
	LenAfterEncrypted(plainLen int) int
	LenAfterDecrypted(cipherLen int) int
	// Encrypt encrypt src to dest
	Encrypt(dest, src []byte)
	// Decrypt decrypt src to dest
	Decrypt(dest, src []byte)
}

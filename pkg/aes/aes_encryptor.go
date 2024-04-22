package aesencryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AES interface
type AES interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

type encryptorAES struct {
	key string
}

// NewAES creates a new aes
func NewAES(key string) AES {
	return &encryptorAES{
		key: key,
	}
}

// Encrypt encrypts the message
func (a *encryptorAES) Encrypt(message string) (string, error) {
	byteMsg := []byte(message)
	block, err := aes.NewCipher([]byte(a.key))
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(byteMsg))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], byteMsg)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt decrypts the message
func (a *encryptorAES) Decrypt(message string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher([]byte(a.key))
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return "", fmt.Errorf("invalid ciphertext block size")
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

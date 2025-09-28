// Package aes provides AES encryption and decryption functionality.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// AES defines the interface for AES encryption and decryption operations.
type AES interface {
	// Encrypt encrypts a plaintext message and returns the base64-encoded ciphertext.
	Encrypt(message string) (string, error)
	// Decrypt decrypts a base64-encoded ciphertext and returns the plaintext message.
	Decrypt(message string) (string, error)
}

// encryptor implements AES encryption using CFB mode with random initialization vectors.
type encryptor struct {
	key string // AES key - must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
}

// NewAES creates a new AES encryptor with the specified key.
// The key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
func NewAES(key string) AES {
	return &encryptor{
		key: key,
	}
}

// Encrypt encrypts the plaintext message using AES in CFB mode with a random IV.
// Returns the encrypted data as a base64-encoded string that includes the IV.
func (a *encryptor) Encrypt(message string) (string, error) {
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

// Decrypt decrypts a base64-encoded ciphertext that was encrypted using Encrypt.
// The ciphertext must include the IV at the beginning.
func (a *encryptor) Decrypt(message string) (string, error) {
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

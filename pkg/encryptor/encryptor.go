package encryptor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	aesencryptor "github.com/sajjanjyothi/encryptor/pkg/aes"
)

var (
	ErrInavlidKeyType = errors.New("Invalid key type")
	ErrKeysExpired    = errors.New("Keys have expired")
)

type Encryptor interface {
	Encrypt(string, string) (string, error)
	Decrypt(string, string) (string, error)
}

type encryptor struct {
	keyType       string
	keys          map[string]time.Time
	keyExpiryTime time.Duration
	keysLock      sync.RWMutex
}

// NewEncryptor creates a new encryptor
func NewEncryptor(keyType string, keyExpiry time.Duration) Encryptor {
	return &encryptor{
		keyType:       keyType,
		keyExpiryTime: keyExpiry,
		keysLock:      sync.RWMutex{},
		keys:          make(map[string]time.Time),
	}
}

// Encrypt encrypts the data
func (e *encryptor) Encrypt(data string, key string) (string, error) {
	plainMessage, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("Failed to decode base64: %w", err)
	}
	switch e.keyType {
	case "aes":
		e.keysLock.Lock()
		defer e.keysLock.Unlock()
		if _, ok := e.keys[key]; !ok {
			slog.Debug("Key not found, creating a new key")
			e.keys[key] = time.Now()
		} else {
			slog.Debug("Key found, checking for expiry")
			if time.Since(e.keys[key]) > e.keyExpiryTime {
				slog.Debug("Key expired")
				return "", ErrKeysExpired
			}
		}
		// AES encryption logic here
		aes := aesencryptor.NewAES(key)
		return aes.Encrypt(string(plainMessage))
	default:
		// Default encryption logic here
		return "", ErrInavlidKeyType
	}
}

// Decrypt decrypts the data
func (e *encryptor) Decrypt(data string, key string) (string, error) {

	switch e.keyType {
	case "aes":
		e.keysLock.Lock()
		defer e.keysLock.Unlock()
		if _, ok := e.keys[key]; !ok {
			e.keys[key] = time.Now()
		} else {
			if time.Since(e.keys[key]) > e.keyExpiryTime {
				return "", ErrKeysExpired
			}
		}
		// AES encryption logic here
		aes := aesencryptor.NewAES(key)
		decryptedText, err := aes.Decrypt(data)
		if err != nil {
			return "", fmt.Errorf("Failed to decrypt: %w", err)
		}
		base64DecryptedText := base64.StdEncoding.EncodeToString([]byte(decryptedText))
		return base64DecryptedText, nil
	default:
		// Default encryption logic here
		return "", ErrInavlidKeyType
	}
}

package encryptor

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sajjanjyothi/encryptor/pkg/aes"
)

const (
	// Supported encryption algorithms
	algorithmAES = "aes"
)

var (
	// ErrInvalidKeyType is returned when an unsupported encryption algorithm is requested.
	ErrInvalidKeyType = errors.New("invalid key type")
	// ErrKeysExpired is returned when encryption keys have expired based on the configured expiry time.
	ErrKeysExpired = errors.New("keys have expired")
)

// Encryptor defines the interface for encryption and decryption operations.
type Encryptor interface {
	// Encrypt encrypts the given data using the specified key.
	// The data should be base64 encoded. Returns the encrypted data as a base64 string.
	Encrypt(data, key string) (string, error)
	// Decrypt decrypts the given encrypted data using the specified key.
	// Returns the decrypted data as a base64 encoded string.
	Decrypt(data, key string) (string, error)
}

// encryptor implements the Encryptor interface with key expiry management.
type encryptor struct {
	keyType       string
	keys          map[string]time.Time
	keyExpiryTime time.Duration
	keysLock      sync.RWMutex
}

// NewEncryptor creates a new encryptor instance with the specified encryption type and key expiry duration.
// keyType specifies the encryption algorithm (currently supports "aes").
// keyExpiry defines how long encryption keys remain valid before expiring.
func NewEncryptor(keyType string, keyExpiry time.Duration) Encryptor {
	return &encryptor{
		keyType:       keyType,
		keyExpiryTime: keyExpiry,
		keysLock:      sync.RWMutex{},
		keys:          make(map[string]time.Time),
	}
}

// Encrypt encrypts the provided base64-encoded data using the specified key.
// It tracks key usage and enforces key expiry based on the configured expiry time.
// Returns the encrypted data as a base64-encoded string or an error if encryption fails.
func (e *encryptor) Encrypt(data string, key string) (string, error) {
	plainMessage, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	switch e.keyType {
	case algorithmAES:
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
		aesImpl := aes.NewAES(key)
		return aesImpl.Encrypt(string(plainMessage))
	default:
		// Default encryption logic here
		return "", ErrInvalidKeyType
	}
}

// Decrypt decrypts the provided encrypted data using the specified key.
// It verifies key validity and enforces key expiry based on the configured expiry time.
// Returns the decrypted data as a base64-encoded string or an error if decryption fails.
func (e *encryptor) Decrypt(data string, key string) (string, error) {

	switch e.keyType {
	case algorithmAES:
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
		aesImpl := aes.NewAES(key)
		decryptedText, err := aesImpl.Decrypt(data)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt: %w", err)
		}
		base64DecryptedText := base64.StdEncoding.EncodeToString([]byte(decryptedText))
		return base64DecryptedText, nil
	default:
		// Default encryption logic here
		return "", ErrInvalidKeyType
	}
}

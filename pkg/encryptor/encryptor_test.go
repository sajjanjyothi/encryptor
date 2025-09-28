package encryptor

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestNewEncryptor(t *testing.T) {
	keyExpiry := 10 * time.Minute
	enc := NewEncryptor("aes", keyExpiry)
	
	if enc == nil {
		t.Error("NewEncryptor should not return nil")
	}
}

func TestEncryptor_Encrypt(t *testing.T) {
	tests := []struct {
		name        string
		keyType     string
		data        string
		key         string
		wantErr     bool
		expectedErr error
	}{
		{
			name:    "valid aes encryption",
			keyType: "aes",
			data:    base64.StdEncoding.EncodeToString([]byte("hello world")),
			key:     "1234567890123456",
			wantErr: false,
		},
		{
			name:        "invalid key type",
			keyType:     "invalid",
			data:        base64.StdEncoding.EncodeToString([]byte("hello world")),
			key:         "1234567890123456",
			wantErr:     true,
			expectedErr: ErrInvalidKeyType,
		},
		{
			name:    "invalid base64 data",
			keyType: "aes",
			data:    "invalid base64",
			key:     "1234567890123456",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := NewEncryptor(tt.keyType, 10*time.Minute)
			_, err := enc.Encrypt(tt.data, tt.key)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Encrypt() expected error but got nil")
				}
				if tt.expectedErr != nil && err != tt.expectedErr {
					t.Errorf("Encrypt() expected error %v but got %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("Encrypt() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestEncryptor_Decrypt(t *testing.T) {
	enc := NewEncryptor("aes", 10*time.Minute)
	key := "1234567890123456"
	originalData := "hello world"
	
	// First encrypt the data
	encodedData := base64.StdEncoding.EncodeToString([]byte(originalData))
	encryptedData, err := enc.Encrypt(encodedData, key)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}
	
	// Then decrypt it
	decryptedData, err := enc.Decrypt(encryptedData, key)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}
	
	// Decode the result
	decodedData, err := base64.StdEncoding.DecodeString(decryptedData)
	if err != nil {
		t.Fatalf("Failed to decode decrypted data: %v", err)
	}
	
	if string(decodedData) != originalData {
		t.Errorf("Decrypted data %q doesn't match original %q", string(decodedData), originalData)
	}
}

func TestEncryptor_KeyExpiry(t *testing.T) {
	enc := NewEncryptor("aes", 1*time.Second)
	key := "1234567890123456"
	data := base64.StdEncoding.EncodeToString([]byte("hello"))
	
	// First encryption should work
	_, err := enc.Encrypt(data, key)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}
	
	// Wait for key to expire
	time.Sleep(2 * time.Second)
	
	// Second encryption should fail
	_, err = enc.Encrypt(data, key)
	if err != ErrKeysExpired {
		t.Errorf("Expected ErrKeysExpired but got %v", err)
	}
}

func TestEncryptor_InvalidKeyType(t *testing.T) {
	enc := NewEncryptor("invalid", 10*time.Minute)
	data := base64.StdEncoding.EncodeToString([]byte("hello"))
	
	_, err := enc.Encrypt(data, "key")
	if err != ErrInvalidKeyType {
		t.Errorf("Expected ErrInvalidKeyType but got %v", err)
	}
	
	_, err = enc.Decrypt("data", "key")
	if err != ErrInvalidKeyType {
		t.Errorf("Expected ErrInvalidKeyType but got %v", err)
	}
}
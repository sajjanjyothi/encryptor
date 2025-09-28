package aes

import (
	"testing"
)

func TestNewAES(t *testing.T) {
	key := "1234567890123456"
	aes := NewAES(key)

	if aes == nil {
		t.Error("NewAES should not return nil")
	}
}

func Test_encryptor_Encrypt(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		message string
		wantErr bool
	}{
		{
			name:    "valid 16-byte key",
			key:     "1234567890123456",
			message: "hello world",
			wantErr: false,
		},
		{
			name:    "invalid key length",
			key:     "foo",
			message: "hello world",
			wantErr: true,
		},
		{
			name:    "valid 24-byte key",
			key:     "123456789012345678901234",
			message: "hello world",
			wantErr: false,
		},
		{
			name:    "valid 32-byte key",
			key:     "12345678901234567890123456789012",
			message: "hello world",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAES(tt.key)
			_, err := a.Encrypt(tt.message)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Encrypt() expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Encrypt() unexpected error: %v", err)
				}
			}
		})
	}
}

func Test_encryptor_Decrypt(t *testing.T) {
	key := "1234567890123456"
	message := "hello world"

	// First encrypt the message
	aes := NewAES(key)
	encrypted, err := aes.Encrypt(message)
	if err != nil {
		t.Fatalf("Failed to encrypt message: %v", err)
	}

	// Then decrypt it
	decrypted, err := aes.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt message: %v", err)
	}

	if decrypted != message {
		t.Errorf("Decrypted message %q doesn't match original %q", decrypted, message)
	}
}

func Test_encryptor_Decrypt_InvalidData(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		message string
		wantErr bool
	}{
		{
			name:    "invalid base64",
			key:     "1234567890123456",
			message: "invalid base64!",
			wantErr: true,
		},
		{
			name:    "too short ciphertext",
			key:     "1234567890123456",
			message: "dGVzdA==", // "test" in base64, too short for IV
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAES(tt.key)
			_, err := a.Decrypt(tt.message)

			if !tt.wantErr {
				t.Errorf("Decrypt() expected no error but got: %v", err)
			} else if err == nil {
				t.Errorf("Decrypt() expected error but got nil")
			}
		})
	}
}

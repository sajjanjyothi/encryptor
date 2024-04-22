package aesencryptor

import (
	"testing"
)

func Test_encryptorAES_Encrypt(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		message string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test Case 1",
			fields: fields{
				key: "1234567890123456",
			},
			args: args{
				message: "bar",
			},
			wantErr: false,
		},
		{
			name: "Test Case 2",
			fields: fields{
				key: "foo",
			},
			args: args{
				message: "bar",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &encryptorAES{
				key: tt.fields.key,
			}
			_, err := a.Encrypt(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptorAES.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_encryptorAES_Decrypt(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		message string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test Case 1",
			fields: fields{
				key: "1234567890123456",
			},
			args: args{
				message: func() string {
					aes := &encryptorAES{
						key: "1234567890123456",
					}
					enc, _ := aes.Encrypt("bar")
					return enc
				}(),
			},
			want:    "bar",
			wantErr: false,
		},
		{
			name: "Test Case 2",
			fields: fields{
				key: "foo",
			},
			args: args{
				message: func() string {
					aes := &encryptorAES{
						key: "foo",
					}
					enc, _ := aes.Encrypt("bar")
					return enc
				}(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &encryptorAES{
				key: tt.fields.key,
			}
			_, err := a.Decrypt(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("encryptorAES.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

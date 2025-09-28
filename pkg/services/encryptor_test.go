package services

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sajjanjyothi/encryptor/api"
	"github.com/sajjanjyothi/encryptor/pkg/encryptor"
	"github.com/stretchr/testify/assert"
)

func TestNewEncryptorService(t *testing.T) {
	enc := encryptor.NewEncryptor("aes", 10*time.Minute)
	service := NewEncryptorService(enc)

	assert.NotNil(t, service)
	assert.NotNil(t, service.EncryptorDecryptor)
}

func TestEncryptorService_GetApiV1List(t *testing.T) {
	enc := encryptor.NewEncryptor("aes", 10*time.Minute)
	service := NewEncryptorService(enc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/list", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := service.GetApiV1List(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response api.ListResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotNil(t, response.Algorithms)
	assert.Contains(t, *response.Algorithms, "aes")
}

func TestEncryptorService_PostApiV1Decrypt_Success(t *testing.T) {
	enc := encryptor.NewEncryptor("aes", 10*time.Minute)
	service := NewEncryptorService(enc)

	// First, get encrypted data
	key := "1234567890123456"
	encryptedData, err := enc.Encrypt("aGVsbG8gd29ybGQ=", key) // base64 of "hello world"
	assert.NoError(t, err)

	// Create request
	algorithm := api.Aes
	reqBody := api.DecryptRequest{
		Algorithm:  &algorithm,
		Cipherkey:  &key,
		Ciphertext: &encryptedData,
	}
	jsonBody, _ := json.Marshal(reqBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", bytes.NewReader(jsonBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err = service.PostApiV1Decrypt(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response api.DecryptedMessage
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotNil(t, response.Message)
}

func TestEncryptorService_PostApiV1Decrypt_InvalidRequest(t *testing.T) {
	enc := encryptor.NewEncryptor("aes", 10*time.Minute)
	service := NewEncryptorService(enc)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", bytes.NewReader([]byte("invalid json")))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := service.PostApiV1Decrypt(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEncryptorService_PostApiV1Decrypt_MissingFields(t *testing.T) {
	enc := encryptor.NewEncryptor("aes", 10*time.Minute)
	service := NewEncryptorService(enc)

	// Request with missing fields
	algorithm := api.Aes
	reqBody := api.DecryptRequest{
		Algorithm: &algorithm,
		// Missing Cipherkey and Ciphertext
	}
	jsonBody, _ := json.Marshal(reqBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", bytes.NewReader(jsonBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := service.PostApiV1Decrypt(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestEncryptorService_PostApiV1Decrypt_InvalidKeyType(t *testing.T) {
	enc := encryptor.NewEncryptor("invalid", 10*time.Minute)
	service := NewEncryptorService(enc)

	key := "1234567890123456"
	ciphertext := "dummy"
	algorithm := api.DecryptRequestAlgorithm("invalid")
	reqBody := api.DecryptRequest{
		Algorithm:  &algorithm,
		Cipherkey:  &key,
		Ciphertext: &ciphertext,
	}
	jsonBody, _ := json.Marshal(reqBody)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", bytes.NewReader(jsonBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := service.PostApiV1Decrypt(c)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

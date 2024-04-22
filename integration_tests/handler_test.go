package tests

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"strings"

	"github.com/labstack/echo/v4"
	"github.com/sajjanjyothi/encryptor/pkg/encryptor"
	"github.com/sajjanjyothi/encryptor/pkg/services"
	"github.com/stretchr/testify/assert"
)

func TestList(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/list", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	encryptorDecryptor := encryptor.NewEncryptor("aes", 10*time.Minute)
	encryptorDecryptorService := services.NewEncryptorService(encryptorDecryptor)

	if assert.NoError(t, encryptorDecryptorService.GetApiV1List(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, `{"algorithms":["aes"]}`, strings.TrimSuffix(rec.Body.String(), "\n"))
	}
}

func TestDecrypt(t *testing.T) {
	encryptorDecryptor := encryptor.NewEncryptor("aes", 10*time.Minute)
	textTobeEncrypted := base64.StdEncoding.EncodeToString([]byte("bar"))
	encryptedText, err := encryptorDecryptor.Encrypt(textTobeEncrypted, "1234567890123456")
	assert.NoError(t, err)
	t.Log(encryptedText)
	requestBody := `{"algorithm":"aes","cipherkey":"1234567890123456","ciphertext":"` + encryptedText + `"}`
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	encryptorDecryptorService := services.NewEncryptorService(encryptorDecryptor)

	if assert.NoError(t, encryptorDecryptorService.PostApiV1Decrypt(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		encodedActualString := base64.StdEncoding.EncodeToString([]byte("bar"))
		assert.Equal(t, `{"message":"`+encodedActualString+`"}`, strings.TrimSuffix(rec.Body.String(), "\n"))
	}
}

func TestDecryptKeyExpiry(t *testing.T) {
	encryptorDecryptor := encryptor.NewEncryptor("aes", 3*time.Second)
	textTobeEncrypted := base64.StdEncoding.EncodeToString([]byte("bar"))
	encryptedText, err := encryptorDecryptor.Encrypt(textTobeEncrypted, "1234567890123456")
	assert.NoError(t, err)
	t.Log(encryptedText)
	requestBody := `{"algorithm":"aes","cipherkey":"1234567890123456","ciphertext":"` + encryptedText + `"}`
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	expiredEncryptorDecryptor := encryptor.NewEncryptor("aes", 1*time.Second)
	encryptorDecryptorService := services.NewEncryptorService(expiredEncryptorDecryptor)
	if assert.NoError(t, encryptorDecryptorService.PostApiV1Decrypt(c)) {
		assert.Equal(t, http.StatusOK, rec.Code)
		encodedActualString := base64.StdEncoding.EncodeToString([]byte("bar"))
		assert.Equal(t, `{"message":"`+encodedActualString+`"}`, strings.TrimSuffix(rec.Body.String(), "\n"))
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/decrypt", strings.NewReader(requestBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	time.Sleep(2 * time.Second) //wait for 2 seconds to expire the key
	if assert.NoError(t, encryptorDecryptorService.PostApiV1Decrypt(c)) {
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, `{"message":"keys expired"}`, strings.TrimSuffix(rec.Body.String(), "\n"))
	}
}

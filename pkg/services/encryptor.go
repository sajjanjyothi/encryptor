// Package services provides HTTP handlers for the encryption/decryption API.
package services

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sajjanjyothi/encryptor/api"
	"github.com/sajjanjyothi/encryptor/pkg/encryptor"
)

// supportedAlgorithms lists the encryption algorithms supported by the service.
var (
	supportedAlgorithms = []string{string(api.Aes)}
)

// EncryptorService provides HTTP handlers for encryption and decryption operations.
type EncryptorService struct {
	EncryptorDecryptor encryptor.Encryptor
}

// NewEncryptorService creates a new service instance with the provided encryptor.
func NewEncryptorService(encryptorDecryptor encryptor.Encryptor) *EncryptorService {
	return &EncryptorService{
		EncryptorDecryptor: encryptorDecryptor,
	}
}

// GetAPIV1List returns the list of supported encryption algorithms.
// It responds with a JSON array of algorithm names.
func (e *EncryptorService) GetApiV1List(ctx echo.Context) error {
	slog.LogAttrs(ctx.Request().Context(), slog.LevelDebug, "List of supported algorithms", slog.Any("algorithms", supportedAlgorithms))
	return ctx.JSON(http.StatusOK, api.ListResponse{
		Algorithms: &supportedAlgorithms,
	})
}

// PostAPIV1Decrypt decrypts ciphertext using the specified algorithm and key.
// It validates the request parameters, performs decryption, and returns the result.
// Returns appropriate HTTP error codes for various failure conditions.
func (e *EncryptorService) PostApiV1Decrypt(ctx echo.Context) error {
	var decryptRequest api.DecryptRequest
	if err := ctx.Bind(&decryptRequest); err != nil {
		slog.Error("Failed to bind request", "error", err)
		response := "invalid request"
		return ctx.JSON(http.StatusBadRequest, api.ErrorResponse{
			Message: &response,
		})
	}

	if decryptRequest.Algorithm == nil || decryptRequest.Cipherkey == nil || decryptRequest.Ciphertext == nil {
		slog.Error("Invalid request, algorithm, cipherkey or ciphertext is missing")
		response := "invalid request"
		return ctx.JSON(http.StatusBadRequest, api.ErrorResponse{
			Message: &response,
		})
	}
	decryptedMessage, err := e.EncryptorDecryptor.Decrypt(*decryptRequest.Ciphertext, *decryptRequest.Cipherkey)
	if err != nil {
		if errors.Is(err, encryptor.ErrInvalidKeyType) {
			slog.LogAttrs(ctx.Request().Context(), slog.LevelError, "invalid key type", slog.Any("error", err))
			response := "invalid key type"
			return ctx.JSON(http.StatusBadRequest, api.ErrorResponse{
				Message: &response,
			})
		} else if errors.Is(err, encryptor.ErrKeysExpired) {
			slog.LogAttrs(ctx.Request().Context(), slog.LevelError, "keys expired", slog.Any("error", err))
			response := "keys expired"
			return ctx.JSON(http.StatusBadRequest, api.ErrorResponse{
				Message: &response,
			})
		} else {
			slog.LogAttrs(ctx.Request().Context(), slog.LevelError, "Failed to decrypt", slog.Any("error", err))
			response := "failed to decrypt"
			return ctx.JSON(http.StatusInternalServerError, api.ErrorResponse{
				Message: &response,
			})
		}
	}
	return ctx.JSON(http.StatusOK, api.DecryptedMessage{
		Message: &decryptedMessage,
	})
}

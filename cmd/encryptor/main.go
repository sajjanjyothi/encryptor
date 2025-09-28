package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sajjanjyothi/encryptor/api"
	"github.com/sajjanjyothi/encryptor/pkg/encryptor"
	"github.com/sajjanjyothi/encryptor/pkg/services"
)

const (
	// Default configuration constants
	keyExpiryTime = 10 * time.Minute
	serverPort    = ":8080"
	staticPath    = "api"

	// Supported encryption algorithms
	defaultAlgorithm = "aes"
)

func main() {
	// Initialize encryptor with AES algorithm and key expiry
	encryptorDecryptor := encryptor.NewEncryptor(defaultAlgorithm, keyExpiryTime)
	encryptorDecryptorService := services.NewEncryptorService(encryptorDecryptor)

	// Set up graceful shutdown channel
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// Configure Echo server
	e := echo.New()
	api.RegisterHandlers(e, encryptorDecryptorService)
	e.Static("/", staticPath) // Serve API documentation

	// Start server in a goroutine
	go func() {
		if err := e.Start(serverPort); err != nil {
			e.Logger.Fatal(err)
		}
	}()

	// Wait for shutdown signal
	<-done

	// Gracefully shutdown the server
	if err := e.Shutdown(context.Background()); err != nil {
		e.Logger.Fatal(err)
	}
}

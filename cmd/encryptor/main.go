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
	keyExpiryTime = 10 * time.Minute
)

func main() {
	encryptorDecryptor := encryptor.NewEncryptor("aes", keyExpiryTime)
	encryptorDecryptorService := services.NewEncryptorService(encryptorDecryptor)
	//wait for signal interrupt to shut down cleanly the server
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	e := echo.New()
	api.RegisterHandlers(e, encryptorDecryptorService)
	e.Static("/", "api") //for api serving swagger ui
	go func() {
		if err := e.Start(":8080"); err != nil {
			e.Logger.Fatal(err)
		}
	}()
	<-done
	if err := e.Shutdown(context.Background()); err != nil {
		e.Logger.Fatal(err)
	}
}

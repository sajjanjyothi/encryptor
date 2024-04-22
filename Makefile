generate:
	oapi-codegen --config=api/config.yaml api/api.yaml
install-oapi:
	go install github.com/deepmap/oapi-codegen/v2/cmd/oapi-codegen@latest
build:
	go build -o bin/encryptor cmd/encryptor/main.go
test:
	go test -v ./...
docker-build:
	docker build -t encryptor:latest -f deployment/Dockerfile .
run:
	go run cmd/encryptor/main.go
lint:
	golangci-lint run -v
clean:
	rm -rf bin
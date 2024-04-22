FROM golang as builder
# pull latest

WORKDIR /app
COPY . .
RUN make build
FROM alpine
RUN   apk update && apk add openssh
WORKDIR /app
COPY --from=builder /app/bin/encryptor /app/encryptor
CMD ["/app/encryptor"]
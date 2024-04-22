## Symmetric Encryption/Decryption service

#### API document can be found in 
[API docs](api/api.yaml)

#### How to run tests (unit tests + integration tests)

```
make test
```

#### How to run the service
```
make run
```
> to access the API doc , navigate to [swagger](http://localhost:8080/index.html)

#### Build and deploy
docker can be build using 
```
make docker-build
```
This docker image can be deployed to any K8S cluster as a service behind an ingress (istio eg:)

#### Code quality
linting can be enforced within CI/CD as

```
make lint
```

#### ToDo
- Keys are stored inside a map within service, This will cause issues on horizontal scaling.This can be moved to cache systems such as **redis**
- API autnentication with JWT
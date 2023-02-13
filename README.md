# Examples

This repository contains examples using the Go Self-Sovereign Identity Framework.

## Start the roles of the ecosystem

issuer: go run cmd/issuer/main.go

holder:	go run cmd/holder/main.go

verifier: go run cmd/verifier/main.go

## Start the process flow

start the issuance flow: curl http://localhost:9081/initIssuance -L

presentation: curl http://localhost:9081/initPresentation -L


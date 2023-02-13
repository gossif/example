// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/gossif/httpserver"
	"github.com/gossif/openidvc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/rs/cors"
	"k8s.io/klog/v2"
)

var (
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  rsa.PublicKey
)

func init() {
	openidvc.SetIssuer("https://localhost:9080")

	rsaPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	rsaPublicKey = rsaPrivateKey.PublicKey
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "pong")
	})
	mux.HandleFunc("/authorize", openidvc.AutorizationRequestHandler)
	mux.HandleFunc("/token", TokenRequestHandler)
	mux.HandleFunc("/credential", CredentialRequestHandler)

	handler := cors.Default().Handler(mux)
	server := httpserver.NewHttpServer(
		httpserver.WithPort("9080"),
		httpserver.WithHandlers(handler),
		httpserver.WithVerbose(false),
	)
	server.Start(context.Background())
}

func TokenRequestHandler(w http.ResponseWriter, r *http.Request) {
	op := openidvc.NewOpenIdProvider()
	tokenRequest, err := op.NewTokenRequest(r)
	if err != nil {
		openidvc.ResponseError(w, handleError(err))
		return
	}
	response, err := tokenRequest.CreateTokenResponse(openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPrivateKey))
	if err != nil {
		openidvc.ResponseError(w, handleError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(response)
}

func CredentialRequestHandler(w http.ResponseWriter, r *http.Request) {
	var (
		response openidvc.CredentialResponse
	)
	issuer := openidvc.NewIssuer()
	// NewCredentialRequest validates also the access_code
	credRequest, err := issuer.NewCredentialRequest(r, openidvc.WithAccessTokenSigningKey(jwa.RS256, rsaPublicKey))
	if err != nil {
		openidvc.CredentialResponseError(w, handleError(err))
		return
	}
	signedCredential := "eyJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZXhhbXBsZToxMjMja2V5LTMiLCJhbGciOiJFUzI1NksifQ.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdzNpZC5vcmcvc2VjdXJpdHkvc3VpdGVzL2p3cy0yMDIwL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmV4YW1wbGU6MTIzIiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0wMS0wMVQxOToyMzoyNFoiLCJjcmVkZW50aWFsU3ViamVjdCI6e319LCJpc3MiOiJkaWQ6ZXhhbXBsZToxMjMiLCJuYmYiOjE2MDk1MjkwMDQsImV4cCI6MTY0MzA3MDI1NSwianRpIjoiOGE3NTMwOTMtMWYwZC00Y2FiLWFhNzMtM2ZhYTAzYjkzNmJiIn0.Hml9P3ErKNfiEGmF8HyY1z4BVl2gpYESx57kfPWmIs4iDM51ZboSH6QaPajtGlRnMw9ZEGprcH2KRtzWHR5OIMBuiWI7pQoBv_lvSvrAqwQL-XHQbjxgP5uaoQfBjvvK"
	response, err = credRequest.CreateCredentialResponse(openidvc.WithVerifiableCredentialn(signedCredential, credRequest.Format))
	if err != nil {
		openidvc.CredentialResponseError(w, handleError(err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(response)
}

func handleError(err error) error {
	if err != nil {
		// notice that we're using 1, so it will actually log the where
		// the error happened, 0 = this function, we don't want that.
		pc, fn, line, _ := runtime.Caller(1)
		// dont show the full path name
		fns := strings.Split(fn, "/github.com/gossif/")
		fnshow := fns[0]
		if len(fns) > 0 {
			fnshow = fns[1]
		}
		klog.Errorf("error in %s[%s:%d] %v", runtime.FuncForPC(pc).Name(), fnshow, line, err)
	}
	return err
}

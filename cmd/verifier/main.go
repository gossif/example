// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gossif/httpserver"
	"github.com/gossif/openidvc"
	"github.com/rs/cors"
	"github.com/spf13/viper"
	"k8s.io/klog/v2"
)

func init() {
	viper.SetDefault("Verifier", "did:ebsi:zZdJzKn42frtX1d23MKEy7F")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "pong")
	})
	mux.HandleFunc("/requestPresentation", func(w http.ResponseWriter, r *http.Request) {
		var (
			PresentDef string = `{"definition_id":"example_ldp_vc","id":"example_ldp_vc_presentation_submission","descriptor_map":[{"id":"id_credential","path":"$","format":"ldp_vp","path_nested":{"format":"ldp_vc","path":"$.verifiableCredential[0]"}}]}`
		)
		nonce, _ := generateNonce()
		state, _ := generateRandomBytes(32)
		authRequest := openidvc.AuthorizationRequest{
			ResponseType: openidvc.VPToken,
			ClientId:     "http://localhost:9082",
			RedirectUri:  "http://localhost:9082/presentation",
			State:        base64.RawStdEncoding.EncodeToString(state),
			PresentDef:   PresentDef,
			Nonce:        nonce,
		}
		authRequest.RedirectPresentationRequest(w, r)
	})
	mux.HandleFunc("/presentation", func(w http.ResponseWriter, r *http.Request) {
		authRequest := openidvc.AuthorizationRequest{
			ClientId: "http://localhost:9082",
		}
		authResponse, err := authRequest.ReceiveAuthorizationResponse(r)
		if err != nil {
			openidvc.CredentialResponseError(w, err)
		}
		klog.Infof("Received presentation: %s", authResponse.PresentationToken)
	})
	handler := cors.Default().Handler(mux)
	server := httpserver.NewHttpServer(
		httpserver.WithPort("9082"),
		httpserver.WithHandlers(handler),
		httpserver.WithVerbose(false),
	)
	server.Start(context.Background())
}

func generateRandomBytes(len int) ([]byte, error) {
	randomBytes := make([]byte, len)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func generateNonce() (string, error) {
	nonceBytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(nonceBytes), nil
}

// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/gossif/httpserver"
	"github.com/gossif/openidvc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/cors"
	"k8s.io/klog/v2"
)

var (
	jwkKeyPublic jwk.Key
)

var (
	plainChallenge = "ThisIsAFourtyThreeCharactersLongStringThing"
	//s256Challenge  = "s256test"
	// echo s256test | sha256 | base64 | tr '/+' '_-'
	//s256ChallengeHash = "W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o="
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "pong")
	})
	// initaite the issuance process
	mux.HandleFunc("/initIssuance", func(w http.ResponseWriter, _ *http.Request) {
		authorizationDetails := []map[string]interface{}{
			{"type": "openid_credential", "format": "jwt_vc_json", "types": []string{"VerifiableCredential", "IDCardCredential"}},
		}
		authorizationDetailsJSON, _ := json.Marshal(authorizationDetails)

		authRequest := openidvc.AuthorizationRequest{
			ResponseType:         "code",
			Scope:                "openid",
			ClientId:             "http://localhost:9081",
			RedirectUri:          "http://localhost:9081/oauth2",
			State:                "123",
			AuthorizationDetails: string(authorizationDetailsJSON),
			CodeChallenge:        plainChallenge,
			CodeChallengeMethod:  "plain",
		}
		requestURL, _ := url.ParseRequestURI("http://localhost:9080/authorize")
		if err := authRequest.PostFormAuthorizationRequest(*requestURL); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Authorization request posted"))
	})
	mux.HandleFunc("/oauth2", func(w http.ResponseWriter, r *http.Request) {
		authRequest := openidvc.AuthorizationRequest{
			ClientId:      "http://localhost:9081",
			RedirectUri:   "http://localhost:9081/oauth2",
			State:         "123",
			CodeChallenge: plainChallenge,
		}
		requestURL, _ := url.ParseRequestURI("http://localhost:9080/token")
		tokenResponse, err := authRequest.PostFormTokenRequest(r, *requestURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response, err := ExchangeCredential(tokenResponse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/initPresentation", InitiatePresentation)

	handler := cors.Default().Handler(mux)

	server := httpserver.NewHttpServer(
		httpserver.WithPort("9081"),
		httpserver.WithHandlers(handler),
		httpserver.WithVerbose(false),
	)
	server.Start(context.Background())
}

func ExchangeCredential(tokenResponse openidvc.TokenResponse) (openidvc.CredentialResponse, error) {
	var (
		credentialResult openidvc.CredentialResponse
	)
	proofJwt, err := generateTokenNatutalPerson(tokenResponse)
	if err != nil {
		return openidvc.CredentialResponse{}, err
	}
	url := "http://localhost:9080/credential"
	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + tokenResponse.AccessToken

	proofOfPossession := map[string]interface{}{"proof_type": "jwt", "jwt": string(proofJwt)}
	credentialRequest := map[string]interface{}{"format": "jwt_vc_json", "types": []string{"VerifiableCredential", "IDCardCredential"}, "proof": proofOfPossession}
	credentialBytes, _ := json.Marshal(credentialRequest)
	// Create a new request using http
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(credentialBytes)))
	if err != nil {
		klog.Errorf("Error on new request - %s", err.Error())
	}
	// add authorization header to the req
	req.Header.Add("Authorization", bearer)
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	// Send req using http Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		klog.Errorf("Error on response - %s", err.Error())
	}
	defer resp.Body.Close()

	dumpbody, _ := httputil.DumpResponse(resp, true)
	klog.Infof("\nRESPONSE:\n%s\n", string(dumpbody))

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&credentialResult)
	if err != nil {
		klog.Errorf("Error while reading the response bytes: %s", err.Error())
	}
	return credentialResult, nil
}

func generateTokenNatutalPerson(tokenResponse openidvc.TokenResponse) ([]byte, error) {
	proof, err := jwt.NewBuilder().
		Issuer("http://localhost:9081").
		Audience([]string{"https://localhost:9080"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute*5)).
		Claim("jwk", jwkKeyPublic).
		Claim("nonce", tokenResponse.CNonce).
		Build()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token - %w", err)
	}
	sigantureKey := `{
		  "kty": "EC",
		  "crv": "P-256",
		  "d": "fjBt4uDWwM-l8_rnLszlzlOodPiOE9iXi1GNokNRtkw",
		  "x": "40TexHWb6XTyuShaqhiazvmfxyK5zibbtOBXsQFKJg8",
		  "y": "SGIGDSRHOOYJntO1lIapw_vR1FP7SPBlmA_2aM9HoFU"
		}`
	jwkKey, err := jwk.ParseKey([]byte(sigantureKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate token - %w", err)
	}
	return jwt.Sign(proof, jwt.WithKey(jwa.ES256, jwkKey))
}

func InitiatePresentation(w http.ResponseWriter, r *http.Request) {
	var (
		authRequest openidvc.AuthorizationRequest
	)
	op := openidvc.NewOpenIdProvider()

	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			var (
				err error
			)
			// Catch the redirect done by the verifier
			authRequest, err = op.NewAuthorizationRequest(req)
			if handleError(err) != nil {
				return http.ErrAbortHandler
			}
			return http.ErrUseLastResponse
		},
	}
	_, err := httpClient.PostForm("http://localhost:9082/requestPresentation", nil)
	if err != nil {
		if err != http.ErrUseLastResponse {
			openidvc.ResponseError(w, handleError(err))
		}
	}
	authResponse, err := PresentationSubmission(authRequest)
	if err != nil {
		openidvc.ResponseError(w, handleError(err))
	}
	response, err := authRequest.CreateAuthorizationResponse(
		openidvc.WithVerifiablePresentation(authResponse.PresentationToken),
		openidvc.WithPresentationSubmission(authResponse.PresentSubmission),
	)
	if err != nil {
		openidvc.ResponseError(w, handleError(err))
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	http.Redirect(w, r, response.String(), http.StatusFound)
}

func PresentationSubmission(_ openidvc.AuthorizationRequest) (openidvc.AuthorizationResponse, error) {
	var (
		presentSubmission string = `{"definition_id":"example_ldp_vc","id":"example_ldp_vc_presentation_submission","descriptor_map":[{"id":"id_credential","path":"$","format":"ldp_vp","path_nested":{"format":"ldp_vc","path":"$.verifiableCredential[0]"}}]}`
	)
	signedPresentation := `{
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"
		],
		"proof": {
			"challenge": "33926830-fa3e-40d9-b85d-748ff32f52d0",
			"created": "2022-08-10T18:08:46.6147225Z",
			"jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..DDTfua7FqP8lA2Ho0P-5QyTYqlpEGmeS0rEWI-KnQiwLEh_YvUu5Aqa8O5yfmGUzr3xKI6YdEFQP6PJa1PYmAg",
			"proofPurpose": "authentication",
			"type": "JsonWebSignature2020",
			"verificationMethod": "did:example:123#key-0"
		},
		"type": "VerifiablePresentation"
	}`
	return openidvc.AuthorizationResponse{
		PresentationToken: signedPresentation,
		PresentSubmission: presentSubmission,
	}, nil
}

func handleError(err error) error {
	if err != nil {
		// notice that we're using 1, so it will actually log the where
		// the error happened, 0 = this function, we don't want that.
		pc, fn, line, _ := runtime.Caller(1)
		// dont show the full path name
		fns := strings.Split(fn, "/github.com/hietkamp/")
		fnshow := fns[0]
		if len(fns) > 0 {
			fnshow = fns[1]
		}
		klog.Errorf("error in %s[%s:%d] %v", runtime.FuncForPC(pc).Name(), fnshow, line, err)
	}
	return err
}

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

const gatewayUserInfoHeader = "X-Apigateway-Api-Userinfo"
const gatewayUserContext = "GATEWAY_USER"

type UserInfo struct {
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Iss           string   `json:"iss"`
	Aud           string   `json:"aud"`
	AuthTime      int      `json:"auth_time"`
	UserID        string   `json:"user_id"`
	Sub           string   `json:"sub"`
	Iat           int      `json:"iat"`
	Exp           int      `json:"exp"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Firebase      Firebase `json:"firebase"`
}
type Identities struct {
	GoogleCom []string `json:"google.com"`
	Email     []string `json:"email"`
}
type Firebase struct {
	Identities     Identities `json:"identities"`
	SignInProvider string     `json:"sign_in_provider"`
}

// handleAuth is a piece of middleware that will parse the gatewayUserInfoHeader from the request and add the UserInfo to the request context
func (s *server) handleAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		encodedUser := r.Header.Get(gatewayUserInfoHeader)
		if encodedUser == "" {
			http.Error(w, "User Not Available", http.StatusForbidden)
			return
		}
		decodedBytes, err := base64.RawURLEncoding.DecodeString(encodedUser)
		if err != nil {
			http.Error(w, "Invalid UserInfo", http.StatusForbidden)
			return
		}
		decoder := json.NewDecoder(bytes.NewReader(decodedBytes))
		var userToken UserInfo
		err = decoder.Decode(&userToken)
		if err != nil {
			http.Error(w, "Invalid UserInfo", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), gatewayUserContext, userToken)
		h.ServeHTTP(w, r.WithContext(ctx))

	}
}

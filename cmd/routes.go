package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (s *server) routes() {
	s.router.HandleFunc("/greet", s.handleAuth(s.handleGreeting()))
}

//handleGreeting will fetch the UserInfo struct that is stored in context from our auth middleware and use that to greet the person that called our api
func (s *server) handleGreeting() http.HandlerFunc {

	type person struct {
		Name string `json:"name"`
	}

	return func(writer http.ResponseWriter, request *http.Request) {

		writer.Header().Set("Content-Type", "application/json")

		// fetch the token user object that is stored in context
		userObj := request.Context().Value(gatewayUserContext).(UserInfo)

		// greet the user 👋
		p := person{Name: fmt.Sprintf("Hello 👋 %s", userObj.Name)}

		decoder := json.NewEncoder(writer)
		if err := decoder.Encode(p); err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
		}
	}
}

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type server struct {
	router *http.ServeMux
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	s := newServer()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	httpServer := &http.Server{Addr: ":" + port, Handler: s, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
	log.Printf("Server Starting on %s", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil {
		return fmt.Errorf("httpServer.ListenAndServe :%v", err)
	}
	return nil
}

func newServer() *server {
	s := &server{http.NewServeMux()}
	s.routes()
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

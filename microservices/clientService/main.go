package main

import (
	"embed"
	"log"
	"net/http"
	"os"
)

//go:embed index.html
var site embed.FS

func main() {
	host := os.Getenv("APP_HOST")
	if host == "" {
		host = "0.0.0.0"
	}
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("acm-app listening on %s:%s", host, port)
	log.Fatal(http.ListenAndServe(host+":"+port, http.FileServer(http.FS(site))))
}

package eaa

import (
	"log"
	"net"
	"net/http"
)

const (
	eaaServerIP   = "localhost"
	eaaServerPort = "8080"
)

// Start Edge Application Agent server listening on port read from config file
func RunEaa() {
	router := NewRouter()
	lis, err := net.Listen("tcp", eaaServerIP+":"+eaaServerPort)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()

	log.Printf("EAA Server started and listening on port %s", eaaServerPort)
	if err = http.Serve(lis, router); err != nil {
		log.Fatal(err)
	}
}

package main

/*
Example using go stdlib net/http ListenAndServeTLS():

	$ go run main.go &

	$ curl -kE ../test-fixtures/client1.pem https://localhost:18080/
	hello, world!

	$ curl -kE ../test-fixtures/client2.pem https://localhost:18080/
	Authentication Failed

	### NOTE: curl on macOS might require using the .p12 file instead of the .pem:
	$ curl -kE ../test-fixtures/client1.p12:password https://localhost:18080/
*/

import (
	"io"
	"log"
	"net/http"

	"github.com/Jaywalker/go-certauth"
	"github.com/Jaywalker/go-certauth/certutils"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "hello, world!\n")
}

func main() {
	caCerts, err := certutils.LoadCACertFile("../test-fixtures/ca.crt")
	if err != nil {
		log.Fatalf("Unable to load ca.crt: %s", err)
	}

	auth := certauth.NewAuth(certauth.Options{
		AllowedOUs: []string{"endpoint"},
		AllowedCNs: []string{"client1"},
	})
	router := auth.Handler(http.HandlerFunc(HelloServer))

	cfg := certutils.TLSServerConfig{
		CertPool:    caCerts,
		BindAddress: "",
		Port:        18080,
		Router:      router,
	}

	server := certutils.NewTLSServer(cfg)
	server.ListenAndServeTLS("../test-fixtures/server.pem", "../test-fixtures/server.pem")
}

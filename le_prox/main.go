package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

// handleTunneling handles HTTPS connections using the CONNECT method.
func handleTunneling(w http.ResponseWriter, r *http.Request) {
	// Remove any extra leading slashes if present.
	host := strings.TrimPrefix(r.Host, "//")

	// Establish a TCP connection to the requested host.
	destConn, err := net.Dial("tcp", host)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Inform the client that the connection has been established.
	w.WriteHeader(http.StatusOK)

	// Hijack the connection so we can start piping raw data.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Start bidirectional data transfer between client and destination.
	go transfer(destConn, clientConn)
	go transfer(clientConn, destConn)
}

// handleHTTP handles regular HTTP requests (non-CONNECT).
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Reset RequestURI (it must be empty when sending requests via http.RoundTrip).
	r.RequestURI = ""

	// Forward the request to the target using the default transport.
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	// Copy the target response headers back to the client.
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	// Write the status code.
	w.WriteHeader(resp.StatusCode)
	// Stream the response body.
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

// transfer facilitates copying data between connections.
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

// handleRequestAndRedirect routes requests to the appropriate handler.
func handleRequestAndRedirect(w http.ResponseWriter, r *http.Request) {
	// Log the request method and URL.
	log.Printf("Received request: %s %s", r.Method, r.URL)
	if r.Method == http.MethodConnect {
		handleTunneling(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func main() {
	// Create an HTTP server listening on port 8080.
	port := 6969
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: http.HandlerFunc(handleRequestAndRedirect),
	}

	log.Printf("Starting proxy server on :%v", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

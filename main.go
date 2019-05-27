//go:generate protoc -I ./proto --go_out=plugins=grpc:./genproto ./proto/grpc_gke.proto

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	pb "github.com/mintenstive/grpc-gke-example/genproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// exampleServer implements the pb.ExampleServiceServer gRPC server interface.
type exampleServer struct{}

func (server *exampleServer) Ping(context context.Context, request *pb.PingRequest) (*pb.PingReply, error) {
	log.Println("ping")

	return &pb.PingReply{
		Message: "hello",
	}, nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	_, err := io.WriteString(w, `<html><body>Welcome to gRPC on GKE example</body></html>`)
	if err != nil {
		log.Printf("index / write response error: %+v", err)
	}

	log.Printf("index: %+v", r)
}

func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.WriteHeader(http.StatusOK)

	_, err := io.WriteString(w, "OK")
	if err != nil {
		log.Printf("health check write response error: %+v", err)
	}

	// Log for debugging purposes so we can see in the container's logs
	// if the health checks are called.
	log.Printf("health check: %+v", r)
}

func startHttpsServer(port string, tlsConfig *tls.Config) error {
	mux := &http.ServeMux{}

	// Health check endpoint will handle all /_ah/* requests
	// e.g. /_ah/live, /_ah/ready and /_ah/lb
	// Create separate routes for specific health requests as needed.
	mux.HandleFunc("/_ah/", handleHealthCheck)
	mux.HandleFunc("/", handleIndex)
	// Add more routes as needed.

	// Set timeouts so that a slow or malicious client doesn't hold resources forever.
	httpsSrv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  60 * time.Second,
		Handler:      mux,
		Addr:         port,
		TLSConfig:    tlsConfig,
	}

	log.Printf("starting HTTP server on port %s", port)

	return httpsSrv.ListenAndServeTLS("", "")
}

func startGrpcServer(port string, tlsConfig *tls.Config) error {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		panic(fmt.Sprintf("gRPC server failed to listen on port '%s': %+v", port, err))
	}

	cred := grpc.Creds(credentials.NewTLS(tlsConfig))
	grpcServer := grpc.NewServer(cred)

	exampleServer := &exampleServer{}
	pb.RegisterExampleServiceServer(grpcServer, exampleServer)

	log.Printf("starting gRPC server on port %s", port)
	return grpcServer.Serve(lis)
}

func getTlsConfig() (*tls.Config, error) {
	// Based on https://benguild.com/2018/11/11/quickstart-golang-kubernetes-grpc-tls-lets-encrypt/
	// https://github.com/benguild/gke-grpc-example/blob/master/main.go
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ipAddress *net.IP

	for _, netInterface := range netInterfaces {
		ipAddresses, err := netInterface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range ipAddresses {
			// check the address type and if it is not a loopback then use it
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ipAddress = &ipnet.IP
				}
			}

			if ipAddress != nil {
				break
			}
		}

		if ipAddress != nil {
			break
		}
	}

	if ipAddress == nil {
		return nil, errors.New("failed to discover IP address")
	}

	log.Printf("server will start at IP: %s", ipAddress.String())

	const certificateValidityInDays = 90
	const certificateBits = 4096

	issuer := pkix.Name{CommonName: ipAddress.String()}

	caCertificate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               issuer,
		Issuer:                issuer,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, certificateValidityInDays),
		SubjectKeyId:          []byte{},
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	privateKey, _ := rsa.GenerateKey(rand.Reader, certificateBits)
	caCertificateBinary, err := x509.CreateCertificate(rand.Reader, caCertificate, caCertificate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	caCertificateParsed, err := x509.ParseCertificate(caCertificateBinary)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCertificateParsed)

	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ServerName:               ipAddress.String(),
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{caCertificateBinary},
			PrivateKey:  privateKey,
		}},
		RootCAs: certPool,
	}

	return tlsConfig, nil
}

func main() {
	// TLS configuration with a self-signed certificate for use between
	// the load balancer (LB) and gRPC & HTTP servers. LB terminates
	// the user TLS connection and communicates with our gRPC servers with
	// a different certificate. user <-> LB: Let's Encrypt certificate
	// LB <-> gRPC server in VPC: self-signed certificate
	// LB <-> HTTPS health check server in VPC: self-signed certificate
	tlsConfig, err := getTlsConfig()
	if err != nil {
		panic(err)
	}

	// Health check server in a goroutine and gRPC server blocking the main,
	// so when the gRPC server crashes it tears down the HTTP server.
	// Thus it cannot respond to the health check calls

	// health check HTTP server
	go func() {
		err = startHttpsServer(":8443", tlsConfig)
		if err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("health check HTTP server failed: %+v", err))
		}
	}()

	// gRPC server
	err = startGrpcServer(":50051", tlsConfig)
	if err != nil {
		panic(fmt.Sprintf("gRPC server failed: %+v", err))
	}

	log.Println("stopping gracefully")
}

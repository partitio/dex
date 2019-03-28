package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/micro/go-micro/client"
	"github.com/micro/go-micro/transport"

	"github.com/partitio/dex/api"
	"github.com/partitio/dex/server"
)

func newDexClient(caPath, clientCrt, clientKey string) (api.DexService, error) {
	cPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("invalid CA crt file: %s", caPath)
	}
	if cPool.AppendCertsFromPEM(caCert) != true {
		return nil, fmt.Errorf("failed to parse CA crt")
	}

	clientCert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client crt file: %s", caPath)
	}

	clientTLSConfig := &tls.Config{
		RootCAs:      cPool,
		Certificates: []tls.Certificate{clientCert},
	}

	c := client.NewClient(client.Transport(transport.NewTransport(transport.TLSConfig(clientTLSConfig))))

	return api.NewDexService(server.DexAPI, c), nil
}

func createPassword(cli api.DexService) error {
	p := api.Password{
		Email: "test@example.com",
		// bcrypt hash of the value "test1" with cost 10
		Hash:     []byte("$2a$10$XVMN/Fid.Ks4CXgzo8fpR.iU1khOMsP5g9xQeXuBm1wXjRX8pjUtO"),
		Username: "test",
		UserId:   "test",
	}

	createReq := &api.CreatePasswordReq{
		Password: &p,
	}

	// Create password.
	if resp, err := cli.CreatePassword(context.TODO(), createReq); err != nil || resp.AlreadyExists {
		if resp.AlreadyExists {
			return fmt.Errorf("Password %s already exists", createReq.Password.Email)
		}
		return fmt.Errorf("failed to create password: %v", err)
	}
	log.Printf("Created password with email %s", createReq.Password.Email)

	// List all passwords.
	resp, err := cli.ListPasswords(context.TODO(), &api.ListPasswordReq{})
	if err != nil {
		return fmt.Errorf("failed to list password: %v", err)
	}

	log.Print("Listing Passwords:\n")
	for _, pass := range resp.Passwords {
		log.Printf("%+v", pass)
	}

	deleteReq := &api.DeletePasswordReq{
		Email: p.Email,
	}

	// Delete password with email = test@example.com.
	if resp, err := cli.DeletePassword(context.TODO(), deleteReq); err != nil || resp.NotFound {
		if resp.NotFound {
			return fmt.Errorf("Password %s not found", deleteReq.Email)
		}
		return fmt.Errorf("failed to delete password: %v", err)
	}
	log.Printf("Deleted password with email %s", deleteReq.Email)

	return nil
}

func main() {
	caCrt := flag.String("ca-crt", "", "CA certificate")
	clientCrt := flag.String("client-crt", "", "Client certificate")
	clientKey := flag.String("client-key", "", "Client key")
	flag.Parse()

	if *clientCrt == "" || *caCrt == "" || *clientKey == "" {
		log.Fatal("Please provide CA & client certificates and client key. Usage: ./client --ca-crt=<path ca.crt> --client-crt=<path client.crt> --client-key=<path client key>")
	}

	client, err := newDexClient(*caCrt, *clientCrt, *clientKey)
	if err != nil {
		log.Fatalf("failed creating dex client: %v ", err)
	}

	if err := createPassword(client); err != nil {
		log.Fatalf("testPassword failed: %v", err)
	}
}

package ldapaggregator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPC is the config for the gRPC API.
type GRPC struct {
	// The port to listen on.
	Addr        string `json:"addr"`
	TLSCert     string `json:"tlsCert"`
	TLSKey      string `json:"tlsKey"`
	TLSClientCA string `json:"tlsClientCA"`
}

func (c *ldapAggregatorConnector) Run() error {
	if !c.ApiEnabled() {
		c.logger.Info("Ldap Aggregator API disabled")
		return nil
	}
	var grpcOptions []grpc.ServerOption

	if c.GRPC.TLSCert != "" {
		// Parse certificates from certificate file and key file for server.
		cert, err := tls.LoadX509KeyPair(c.GRPC.TLSCert, c.GRPC.TLSKey)
		if err != nil {
			return fmt.Errorf("invalid config: error parsing gRPC certificate file: %v", err)
		}

		tlsConfig := tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			CipherSuites:             allowedTLSCiphers,
			PreferServerCipherSuites: true,
		}

		if c.GRPC.TLSClientCA != "" {
			// Parse certificates from client CA file to a new CertPool.
			cPool := x509.NewCertPool()
			clientCert, err := ioutil.ReadFile(c.GRPC.TLSClientCA)
			if err != nil {
				return fmt.Errorf("invalid config: reading from client CA file: %v", err)
			}
			if !cPool.AppendCertsFromPEM(clientCert) {
				return errors.New("invalid config: failed to parse client CA")
			}

			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = cPool
		}

		grpcOptions = append(grpcOptions, grpc.Creds(credentials.NewTLS(&tlsConfig)))
	}
	list, err := net.Listen("tcp", c.GRPC.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s failed: %v", c.GRPC.Addr, err)
	}
	s := grpc.NewServer(grpcOptions...)
	RegisterLdapAggregatorServer(s, c)
	go func() {
		c.logger.Infof("ldap-aggregator: grpc api listening on %s", c.GRPC.Addr)
		if err := s.Serve(list); err != nil {
			c.logger.Error(err)
		}
	}()
	return nil
}

func (c *ldapAggregatorConnector) List(ctx context.Context, req *ListRequest) (*ListResponse, error) {
	c.m.RLock()
	defer c.m.Unlock()
	res, err := c.LdapAggregatorDefaultServer.List(ctx, req)
	if err != nil {
		return nil, err
	}
	for k, v := range res.Results {
		v.BindPw = ""
		res.Results[k] = v
	}
	return res, nil
}

func (c *ldapAggregatorConnector) Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	c.m.Lock()
	defer c.m.Unlock()
	conn, err := req.Payload.OpenConnector(c.logger)
	if err != nil {
		return nil, err
	}
	c.ldapConnectors = append(c.ldapConnectors, &ldapServer{
		conf: *req.Payload,
		conn: conn,
	})
	res, err := c.LdapAggregatorDefaultServer.Create(ctx, req)
	if err != nil {
		return nil, err
	}
	res.Result.BindPw = ""
	return res, nil
}

func (c *ldapAggregatorConnector) Read(ctx context.Context, req *ReadRequest) (*ReadResponse, error) {
	c.m.RLock()
	defer c.m.Unlock()
	res, err := c.LdapAggregatorDefaultServer.Read(ctx, req)
	if err != nil {
		return nil, err
	}
	res.Result.BindPw = ""
	return res, nil
}

func (c *ldapAggregatorConnector) Update(ctx context.Context, req *UpdateRequest) (*UpdateResponse, error) {
	c.m.Lock()
	defer c.m.Unlock()
	index := -1
	for i := range c.ldapConnectors {
		if c.ldapConnectors[i].conf.Host == req.Payload.Host {
			index = i
			break
		}
	}
	if index == -1 {
		return &UpdateResponse{NotFound: true}, fmt.Errorf("%s not found", req.Payload.Host)
	}
	conn, err := req.Payload.OpenConnector(c.logger)
	if err != nil {
		return nil, err
	}
	c.ldapConnectors[index] = &ldapServer{
		conf: *req.Payload,
		conn: conn,
	}
	res, err := c.LdapAggregatorDefaultServer.Update(ctx, req)
	if err != nil {
		return nil, err
	}
	res.Result.BindPw = ""
	return res, nil
}

func (c *ldapAggregatorConnector) Delete(ctx context.Context, req *DeleteRequest) (*DeleteResponse, error) {
	c.m.Lock()
	defer c.m.Unlock()
	index := -1
	for i := range c.ldapConnectors {
		if c.ldapConnectors[i].conf.Host == req.Id {
			index = i
			c.ldapConnectors = append(c.ldapConnectors[:i], c.ldapConnectors[i+1:]...)
			break
		}
	}
	if index == -1 {
		return &DeleteResponse{NotFound: true}, fmt.Errorf("%s not found", req.Id)
	}
	return &DeleteResponse{}, nil
}

var allowedTLSCiphers = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

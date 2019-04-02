package dex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/micro/go-micro"
	"github.com/micro/go-micro/transport"

	mprom "github.com/micro/go-plugins/wrapper/monitoring/prometheus"
	"github.com/partitio/dex/api"
	"github.com/partitio/dex/pkg/log"
	"github.com/partitio/dex/server"
	"github.com/partitio/dex/storage"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// RegisterConnector allows to register a dex connector dynamically
// Il should be registered before creating a dex instance
func RegisterConnector(name string, config func() server.ConnectorConfig) error {
	if _, ok := server.ConnectorsConfig[name]; ok {
		return errors.New("connector name already exists")
	}
	if config == nil {
		return errors.New("config cannot be nil")
	}
	server.ConnectorsConfig[name] = config
	return nil
}

type dex struct {
	config       Config
	serverConfig server.Config

	logger             log.Logger
	prometheusRegistry prometheus.Gatherer
	options            []micro.Option
}

// NewDex create a new dex instance from the config c
func NewDex(c Config) (*dex, error) {
	logger, err := newLogger(c.Logger.Level, c.Logger.Format)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	if c.Logger.Level != "" {
		logger.Infof("config using log level: %s", c.Logger.Level)
	}

	// Fast checks. Perform these first for a more responsive CLI.
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{c.Issuer == "", "no issuer specified in config file"},
		{!c.EnablePasswordDB && len(c.StaticPasswords) != 0, "cannot specify static passwords without enabling password db"},
		{c.Storage.Config == nil, "no storage supplied in config file"},
		{c.Web.HTTP == "" && c.Web.HTTPS == "", "must supply a HTTP/HTTPS  address to listen on"},
		{c.Web.HTTPS != "" && c.Web.TLSCert == "", "no cert specified for HTTPS"},
		{c.Web.HTTPS != "" && c.Web.TLSKey == "", "no private key specified for HTTPS"},
		{c.GRPC.TLSCert != "" && c.GRPC.Addr == "", "no address specified for gRPC"},
		{c.GRPC.TLSKey != "" && c.GRPC.Addr == "", "no address specified for gRPC"},
		{(c.GRPC.TLSCert == "") != (c.GRPC.TLSKey == ""), "must specific both a gRPC TLS cert and key"},
		{c.GRPC.TLSCert == "" && c.GRPC.TLSClientCA != "", "cannot specify gRPC TLS client CA without a gRPC TLS cert"},
	}

	for _, check := range checks {
		if check.bad {
			return nil, fmt.Errorf("invalid config: %s", check.errMsg)
		}
	}

	logger.Infof("config issuer: %s", c.Issuer)

	prometheusRegistry := prometheus.NewRegistry()
	err = prometheusRegistry.Register(prometheus.NewGoCollector())
	if err != nil {
		return nil, fmt.Errorf("failed to register Go runtime metrics: %v", err)
	}

	err = prometheusRegistry.Register(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{
		PidFn: func() (i int, e error) {
			return os.Getpid(), nil
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to register process metrics: %v", err)
	}

	//grpcMetrics := grpcprometheus.NewServerMetrics()
	//err = prometheusRegistry.Register(grpcMetrics)
	//if err != nil {
	//	return fmt.Errorf("failed to register gRPC server metrics: %v", err)
	//}

	var options []micro.Option

	if c.GRPC.TLSCert != "" {
		// Parse certificates from certificate file and key file for server.
		cert, err := tls.LoadX509KeyPair(c.GRPC.TLSCert, c.GRPC.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("invalid config: error parsing gRPC certificate file: %v", err)
		}

		tlsConfig := tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		}

		if c.GRPC.TLSClientCA != "" {
			// Parse certificates from client CA file to a new CertPool.
			cPool := x509.NewCertPool()
			clientCert, err := ioutil.ReadFile(c.GRPC.TLSClientCA)
			if err != nil {
				return nil, fmt.Errorf("invalid config: reading from client CA file: %v", err)
			}
			if cPool.AppendCertsFromPEM(clientCert) != true {
				return nil, errors.New("invalid config: failed to parse client CA")
			}

			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = cPool

		}
		options = append(options, micro.Transport(transport.NewTransport(transport.TLSConfig(&tlsConfig))))
	}

	s, err := c.Storage.Config.Open(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %v", err)
	}
	logger.Infof("config storage: %s", c.Storage.Type)

	if len(c.StaticClients) > 0 {
		for _, client := range c.StaticClients {
			logger.Infof("config static client: %s", client.ID)
		}
		s = storage.WithStaticClients(s, c.StaticClients)
	}
	if len(c.StaticPasswords) > 0 {
		passwords := make([]storage.Password, len(c.StaticPasswords))
		for i, p := range c.StaticPasswords {
			passwords[i] = storage.Password(p)
		}
		s = storage.WithStaticPasswords(s, passwords, logger)
	}

	storageConnectors := make([]storage.Connector, len(c.StaticConnectors))
	for i, c := range c.StaticConnectors {
		if c.ID == "" || c.Name == "" || c.Type == "" {
			return nil, fmt.Errorf("invalid config: ID, Type and Name fields are required for a connector")
		}
		if c.Config == nil {
			return nil, fmt.Errorf("invalid config: no config field for connector %q", c.ID)
		}
		logger.Infof("config connector: %s", c.ID)

		// convert to a storage connector object
		conn, err := ToStorageConnector(c)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize storage connectors: %v", err)
		}
		storageConnectors[i] = conn

	}

	if c.EnablePasswordDB {
		storageConnectors = append(storageConnectors, storage.Connector{
			ID:   server.LocalConnector,
			Name: "Email",
			Type: server.LocalConnector,
		})
		logger.Infof("config connector: local passwords enabled")
	}

	s = storage.WithStaticConnectors(s, storageConnectors)

	if len(c.OAuth2.ResponseTypes) > 0 {
		logger.Infof("config response types accepted: %s", c.OAuth2.ResponseTypes)
	}
	if c.OAuth2.SkipApprovalScreen {
		logger.Infof("config skipping approval screen")
	}
	if c.OAuth2.PasswordConnector != "" {
		logger.Infof("config using password grant connector: %s", c.OAuth2.PasswordConnector)
	}
	if len(c.Web.AllowedOrigins) > 0 {
		logger.Infof("config allowed origins: %s", c.Web.AllowedOrigins)
	}

	// explicitly convert to UTC.
	now := func() time.Time { return time.Now().UTC() }

	serverConfig := server.Config{
		SupportedResponseTypes: c.OAuth2.ResponseTypes,
		SkipApprovalScreen:     c.OAuth2.SkipApprovalScreen,
		PasswordConnector:      c.OAuth2.PasswordConnector,
		AllowedOrigins:         c.Web.AllowedOrigins,
		Issuer:                 c.Issuer,
		Storage:                s,
		Web:                    c.Frontend,
		Logger:                 logger,
		Now:                    now,
		PrometheusRegistry:     prometheusRegistry,
	}
	if c.Expiry.SigningKeys != "" {
		signingKeys, err := time.ParseDuration(c.Expiry.SigningKeys)
		if err != nil {
			return nil, fmt.Errorf("invalid config value %q for signing keys expiry: %v", c.Expiry.SigningKeys, err)
		}
		logger.Infof("config signing keys expire after: %v", signingKeys)
		serverConfig.RotateKeysAfter = signingKeys
	}
	if c.Expiry.IDTokens != "" {
		idTokens, err := time.ParseDuration(c.Expiry.IDTokens)
		if err != nil {
			return nil, fmt.Errorf("invalid config value %q for id token expiry: %v", c.Expiry.IDTokens, err)
		}
		logger.Infof("config id tokens valid for: %v", idTokens)
		serverConfig.IDTokensValidFor = idTokens
	}
	if c.Expiry.AuthRequests != "" {
		authRequests, err := time.ParseDuration(c.Expiry.AuthRequests)
		if err != nil {
			return nil, fmt.Errorf("invalid config value %q for auth request expiry: %v", c.Expiry.AuthRequests, err)
		}
		logger.Infof("config auth requests valid for: %v", authRequests)
		serverConfig.AuthRequestsValidFor = authRequests
	}
	return &dex{c, serverConfig, logger, prometheusRegistry, options}, nil
}

// Run launch the dex instance servers
func (d *dex) Run() error {
	serv, err := server.NewServer(context.Background(), d.serverConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize server: %v", err)
	}

	telemetryServ := http.NewServeMux()
	telemetryServ.Handle("/metrics", promhttp.HandlerFor(d.prometheusRegistry, promhttp.HandlerOpts{}))

	errc := make(chan error, 3)
	if d.config.Telemetry.HTTP != "" {
		d.logger.Infof("listening (http/telemetry) on %s", d.config.Telemetry.HTTP)
		go func() {
			err := http.ListenAndServe(d.config.Telemetry.HTTP, telemetryServ)
			errc <- fmt.Errorf("listening on %s failed: %v", d.config.Telemetry.HTTP, err)
		}()
	}
	if d.config.Web.HTTP != "" {
		d.logger.Infof("listening (http) on %s", d.config.Web.HTTP)
		go func() {
			err := http.ListenAndServe(d.config.Web.HTTP, serv)
			errc <- fmt.Errorf("listening on %s failed: %v", d.config.Web.HTTP, err)
		}()
	}
	if d.config.Web.HTTPS != "" {
		httpsSrv := &http.Server{
			Addr:    d.config.Web.HTTPS,
			Handler: serv,
			TLSConfig: &tls.Config{
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS12,
			},
		}

		d.logger.Infof("listening (https) on %s", d.config.Web.HTTPS)
		go func() {
			err = httpsSrv.ListenAndServeTLS(d.config.Web.TLSCert, d.config.Web.TLSKey)
			errc <- fmt.Errorf("listening on %s failed: %v", d.config.Web.HTTPS, err)
		}()
	}
	if d.config.GRPC.Addr != "" {
		d.logger.Infof("listening (grpc) on %s", d.config.GRPC.Addr)
		d.options = append(d.options, micro.Address(d.config.GRPC.Addr))
		go func() {
			errc <- func() error {
				d.options = append(d.options,
					micro.Name(server.DexAPI),
					micro.WrapHandler(mprom.NewHandlerWrapper()),
				)
				s := micro.NewService(d.options...)
				if err := api.RegisterDexHandler(s.Server(), server.NewAPI(d.serverConfig.Storage, d.logger)); err != nil {
					return err
				}
				//grpcMetrics.InitializeMetrics(s)
				err = s.Run()
				return fmt.Errorf("listening on %s failed: %v", d.config.GRPC.Addr, err)
			}()
		}()
	}

	return <-errc
}

var (
	logLevels  = []string{"debug", "info", "error"}
	logFormats = []string{"json", "text"}
)

type utcFormatter struct {
	f logrus.Formatter
}

func (f *utcFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return f.f.Format(e)
}

func newLogger(level string, format string) (log.Logger, error) {
	var logLevel logrus.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = logrus.DebugLevel
	case "", "info":
		logLevel = logrus.InfoLevel
	case "error":
		logLevel = logrus.ErrorLevel
	default:
		return nil, fmt.Errorf("log level is not one of the supported values (%s): %s", strings.Join(logLevels, ", "), level)
	}

	var formatter utcFormatter
	switch strings.ToLower(format) {
	case "", "text":
		formatter.f = &logrus.TextFormatter{DisableColors: true}
	case "json":
		formatter.f = &logrus.JSONFormatter{}
	default:
		return nil, fmt.Errorf("log format is not one of the supported values (%s): %s", strings.Join(logFormats, ", "), format)
	}

	return &logrus.Logger{
		Out:       os.Stderr,
		Formatter: &formatter,
		Level:     logLevel,
	}, nil
}

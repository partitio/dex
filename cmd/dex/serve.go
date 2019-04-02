package main

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

	"github.com/ghodss/yaml"
	"github.com/micro/go-micro"
	"github.com/micro/go-micro/transport"
	mprom "github.com/micro/go-plugins/wrapper/monitoring/prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/partitio/dex/api"
	"github.com/partitio/dex/pkg/log"
	"github.com/partitio/dex/server"
	"github.com/partitio/dex/storage"
)

func commandServe() *cobra.Command {
	return &cobra.Command{
		Use:     "serve [ config file ]",
		Short:   "Connect to the storage and begin serving requests.",
		Long:    ``,
		Example: "dex serve config.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
		},
	}
}

func serve(cmd *cobra.Command, args []string) error {
	switch len(args) {
	default:
		return errors.New("surplus arguments")
	case 0:
		// TODO(ericchiang): Consider having a default config file location.
		return errors.New("no arguments provided")
	case 1:
	}

	configFile := args[0]
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %v", configFile, err)
	}

	var c Config
	if err := yaml.Unmarshal(configData, &c); err != nil {
		return fmt.Errorf("error parse config file %s: %v", configFile, err)
	}

	d, err := NewDex(c)
	if err != nil {
		return err
	}
	return d.Run()
}

type Dex struct {
	config Config
	logger log.Logger
}

func NewDex(c Config) (*Dex, error) {
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
	return &Dex{c, logger}, nil
}

func (d *Dex) Run() error {
	d.logger.Infof("config issuer: %s", d.config.Issuer)

	prometheusRegistry := prometheus.NewRegistry()
	err := prometheusRegistry.Register(prometheus.NewGoCollector())
	if err != nil {
		return fmt.Errorf("failed to register Go runtime metrics: %v", err)
	}

	err = prometheusRegistry.Register(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{
		PidFn: func() (i int, e error) {
			return os.Getpid(), nil
		},
	}))
	if err != nil {
		return fmt.Errorf("failed to register process metrics: %v", err)
	}

	//grpcMetrics := grpcprometheus.NewServerMetrics()
	//err = prometheusRegistry.Register(grpcMetrics)
	//if err != nil {
	//	return fmt.Errorf("failed to register gRPC server metrics: %v", err)
	//}

	var options []micro.Option

	if d.config.GRPC.TLSCert != "" {
		// Parse certificates from certificate file and key file for server.
		cert, err := tls.LoadX509KeyPair(d.config.GRPC.TLSCert, d.config.GRPC.TLSKey)
		if err != nil {
			return fmt.Errorf("invalid config: error parsing gRPC certificate file: %v", err)
		}

		tlsConfig := tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
		}

		if d.config.GRPC.TLSClientCA != "" {
			// Parse certificates from client CA file to a new CertPool.
			cPool := x509.NewCertPool()
			clientCert, err := ioutil.ReadFile(d.config.GRPC.TLSClientCA)
			if err != nil {
				return fmt.Errorf("invalid config: reading from client CA file: %v", err)
			}
			if cPool.AppendCertsFromPEM(clientCert) != true {
				return errors.New("invalid config: failed to parse client CA")
			}

			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			tlsConfig.ClientCAs = cPool

		}
		options = append(options, micro.Transport(transport.NewTransport(transport.TLSConfig(&tlsConfig))))
	}

	s, err := d.config.Storage.Config.Open(d.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}
	d.logger.Infof("config storage: %s", d.config.Storage.Type)

	if len(d.config.StaticClients) > 0 {
		for _, client := range d.config.StaticClients {
			d.logger.Infof("config static client: %s", client.ID)
		}
		s = storage.WithStaticClients(s, d.config.StaticClients)
	}
	if len(d.config.StaticPasswords) > 0 {
		passwords := make([]storage.Password, len(d.config.StaticPasswords))
		for i, p := range d.config.StaticPasswords {
			passwords[i] = storage.Password(p)
		}
		s = storage.WithStaticPasswords(s, passwords, d.logger)
	}

	storageConnectors := make([]storage.Connector, len(d.config.StaticConnectors))
	for i, c := range d.config.StaticConnectors {
		if c.ID == "" || c.Name == "" || c.Type == "" {
			return fmt.Errorf("invalid config: ID, Type and Name fields are required for a connector")
		}
		if c.Config == nil {
			return fmt.Errorf("invalid config: no config field for connector %q", c.ID)
		}
		d.logger.Infof("config connector: %s", c.ID)

		// convert to a storage connector object
		conn, err := ToStorageConnector(c)
		if err != nil {
			return fmt.Errorf("failed to initialize storage connectors: %v", err)
		}
		storageConnectors[i] = conn

	}

	if d.config.EnablePasswordDB {
		storageConnectors = append(storageConnectors, storage.Connector{
			ID:   server.LocalConnector,
			Name: "Email",
			Type: server.LocalConnector,
		})
		d.logger.Infof("config connector: local passwords enabled")
	}

	s = storage.WithStaticConnectors(s, storageConnectors)

	if len(d.config.OAuth2.ResponseTypes) > 0 {
		d.logger.Infof("config response types accepted: %s", d.config.OAuth2.ResponseTypes)
	}
	if d.config.OAuth2.SkipApprovalScreen {
		d.logger.Infof("config skipping approval screen")
	}
	if d.config.OAuth2.PasswordConnector != "" {
		d.logger.Infof("config using password grant connector: %s", d.config.OAuth2.PasswordConnector)
	}
	if len(d.config.Web.AllowedOrigins) > 0 {
		d.logger.Infof("config allowed origins: %s", d.config.Web.AllowedOrigins)
	}

	// explicitly convert to UTC.
	now := func() time.Time { return time.Now().UTC() }

	serverConfig := server.Config{
		SupportedResponseTypes: d.config.OAuth2.ResponseTypes,
		SkipApprovalScreen:     d.config.OAuth2.SkipApprovalScreen,
		PasswordConnector:      d.config.OAuth2.PasswordConnector,
		AllowedOrigins:         d.config.Web.AllowedOrigins,
		Issuer:                 d.config.Issuer,
		Storage:                s,
		Web:                    d.config.Frontend,
		Logger:                 d.logger,
		Now:                    now,
		PrometheusRegistry:     prometheusRegistry,
	}
	if d.config.Expiry.SigningKeys != "" {
		signingKeys, err := time.ParseDuration(d.config.Expiry.SigningKeys)
		if err != nil {
			return fmt.Errorf("invalid config value %q for signing keys expiry: %v", d.config.Expiry.SigningKeys, err)
		}
		d.logger.Infof("config signing keys expire after: %v", signingKeys)
		serverConfig.RotateKeysAfter = signingKeys
	}
	if d.config.Expiry.IDTokens != "" {
		idTokens, err := time.ParseDuration(d.config.Expiry.IDTokens)
		if err != nil {
			return fmt.Errorf("invalid config value %q for id token expiry: %v", d.config.Expiry.IDTokens, err)
		}
		d.logger.Infof("config id tokens valid for: %v", idTokens)
		serverConfig.IDTokensValidFor = idTokens
	}
	if d.config.Expiry.AuthRequests != "" {
		authRequests, err := time.ParseDuration(d.config.Expiry.AuthRequests)
		if err != nil {
			return fmt.Errorf("invalid config value %q for auth request expiry: %v", d.config.Expiry.AuthRequests, err)
		}
		d.logger.Infof("config auth requests valid for: %v", authRequests)
		serverConfig.AuthRequestsValidFor = authRequests
	}

	serv, err := server.NewServer(context.Background(), serverConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize server: %v", err)
	}

	telemetryServ := http.NewServeMux()
	telemetryServ.Handle("/metrics", promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))

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
		options = append(options, micro.Address(d.config.GRPC.Addr))
		go func() {
			errc <- func() error {
				options = append(options,
					micro.Name(server.DexAPI),
					micro.WrapHandler(mprom.NewHandlerWrapper()),
				)
				s := micro.NewService(options...)
				if err := api.RegisterDexHandler(s.Server(), server.NewAPI(serverConfig.Storage, d.logger)); err != nil {
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

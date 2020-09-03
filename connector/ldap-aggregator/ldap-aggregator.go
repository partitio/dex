// Package ldap implements strategies for authenticating using the LDAP protocol.
package ldapaggregator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"google.golang.org/grpc"
	"gopkg.in/ldap.v2"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds the configuration parameters for the LDAP connector. The LDAP
// connectors require executing two queries, the first to find the user based on
// the username and password given to the connector. The second to use the user
// entry to search for groups.
//
// An example config:
//
//     type: ldap-aggregator
//     config:
//       # if not set server is disabled
//       grpc:
//         addr: 127.0.0.1:5559
//         tlsCert: examples/grpc-client/server.crt
//         tlsKey: examples/grpc-client/server.key
//         tlsClientCA: /etc/dex/client.crt
// 		 # SQLite can be used as db engine
//       sqlite: ./ldap-aggregator.db
// 		 # Postgres will overide any SQLite configuration
//       postgres:
//	       host: postgres
//	       port: 5432
//	       ssl: false
//	       username: dex
//	       password: P@ssword
//	       database: ldap
//       # servers are only used to bootstrap some ldap servers
//       # once the database is initialized, the database will override
//       # on any duplicated ldap server configuration
//       servers:
//       - host: ldap.example.com:636
//       # The following field is required if using port 389.
//       # insecureNoSSL: true
//         rootCA: /etc/dex/ldap.ca
//         bindDN: uid=seviceaccount,cn=users,dc=example,dc=com
//         bindPW: password
//         userSearch:
//           # Would translate to the query "(&(objectClass=person)(uid=<username>))"
//           baseDN: cn=users,dc=example,dc=com
//           filter: "(objectClass=person)"
//           username: uid
//           idAttr: uid
//           emailAttr: mail
//           nameAttr: name
//         groupSearch:
//           # Would translate to the query "(&(objectClass=group)(member=<user uid>))"
//           baseDN: cn=groups,dc=example,dc=com
//           filter: "(objectClass=group)"
//           userAttr: uid
//           # Use if full DN is needed and not available as any other attribute
//           # Will only work if "DN" attribute does not exist in the record
//           # userAttr: DN
//           groupAttr: member
//           nameAttr: name
//
type Config struct {
	GRPC     *GRPC           `json:"grpc"`
	Postgres *PostgresConfig `json:"postgres"`
	Sqlite   string          `json:"sqlite"`
	// PassPhrase is used to encrypt ldap's BindPW
	PassPhrase string        `json:"passPhrase"`
	Servers    []*LdapConfig `json:"servers"`
	// UsernamePrompt allows users to override the username attribute (displayed
	// in the username/password prompt). If unset, the handler will use
	// "Username".
	UsernamePrompt string `json:"usernamePrompt"`
}

func (c *Config) ApiEnabled() bool {
	return c.GRPC != nil
}

type PostgresConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	SSL      bool   `json:"ssl"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// Open returns an authentication strategy using LDAP.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	conn, err := c.OpenConnector(logger)
	if err != nil {
		return nil, err
	}
	return connector.Connector(conn), nil
}

// OpenConnector is the same as Open but returns a type with all implemented connector interfaces.
func (c *Config) OpenConnector(logger log.Logger) (interface {
	connector.Connector
	connector.PasswordConnector
	connector.RefreshConnector
	io.Closer
}, error) {
	return c.openConnector(logger)
}

func (c *Config) openConnector(logger log.Logger) (*ldapAggregatorConnector, error) {
	var db *gorm.DB
	var err error
	if !c.ApiEnabled() && len(c.Servers) == 0 {
		return nil, errors.New("servers cannot be empty when api is not enabled")
	}
	if c.ApiEnabled() {
		if c.PassPhrase == "" {
			return nil, errors.New("PassPhrase cannot be empty when api is enabled")
		}
		// Initialize Password Crypto
		crypto, err = NewCrypto(c.PassPhrase)
		if err != nil {
			return nil, err
		}
		db, err = c.openGormDB()
		if err != nil {
			return nil, fmt.Errorf("failed to connect to database: %v", err)
		}
		if err := db.AutoMigrate(&LdapConfigORM{}).Error; err != nil {
			return nil, fmt.Errorf("failed to migrate database: %v", err)
		}
		db = db.Set("gorm:auto_preload", true)
		// Check if db contains ldap servers
		ss, err := DefaultListLdapConfig(context.Background(), db)
		if err != nil {
			return nil, err
		}
		// Append servers from config file after db servers as db take precedence over config file
		c.Servers = append(ss, c.Servers...)
	}
	var ldapServers []*ldapServer
	for i, ldapConfig := range c.Servers {
		if err := ldapConfig.Validate(); err != nil {
			return nil, fmt.Errorf("invalid configuration for %s : %v", ldapConfig.Host, err)
		}
		if i > 0 && contains(c.Servers[:i], ldapConfig) {
			logger.Infof("skipping %s as it is present in database", ldapConfig.Host)
			continue
		}
		conn, err := ldapConfig.OpenConnector(logger)
		if err != nil {
			logger.Errorf("invalid aggregated ldap: %s", err)
			continue
		}
		ldapConfig.Id = ldapConfig.Host
		if c.ApiEnabled() {
			if _, err := DefaultStrictUpdateLdapConfig(context.Background(), ldapConfig, db); err != nil {
				return nil, fmt.Errorf("falied to save %s in db: %v", ldapConfig.Host, err)
			}
		}
		ldapServers = append(ldapServers, &ldapServer{*ldapConfig, conn})
	}
	conn := &ldapAggregatorConnector{db: db, Config: *c, ldapConnectors: ldapServers, logger: logger, LdapAggregatorDefaultGRPCServer: NewLdapAggregatorDefaultGRPCServer(db)}
	err = conn.Run()
	return conn, err
}

func (c *Config) openGormDB() (*gorm.DB, error) {
	if c.Postgres == nil {
		if c.Sqlite != "" {
			return gorm.Open("sqlite3", c.Sqlite)
		}
		return nil, errors.New("ldap-aggregator: no db config")
	}
	dbPath := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s",
		c.Postgres.Username,
		c.Postgres.Password,
		c.Postgres.Host,
		c.Postgres.Port,
		c.Postgres.Database,
	)
	if !c.Postgres.SSL {
		dbPath += " sslmode=disable"
	}
	return gorm.Open("postgres", dbPath)
}

func (c *ldapAggregatorConnector) Close() error {
	if c.grpc != nil {
		c.grpc.GracefulStop()
	}
	return c.db.Close()
}

type ldapServer struct {
	conf LdapConfig
	conn interface {
		connector.Connector
		connector.PasswordConnector
		connector.RefreshConnector
	}
}

type ldapAggregatorConnector struct {
	Config
	ldapConnectors []*ldapServer
	logger         log.Logger
	m              sync.RWMutex
	grpc           *grpc.Server
	*LdapAggregatorDefaultGRPCServer
	db *gorm.DB
}

type refreshData struct {
	Username string     `json:"username"`
	Entry    ldap.Entry `json:"entry"`
	Source   string     `json:"source"`
}

var (
	_ connector.PasswordConnector = (*ldapAggregatorConnector)(nil)
	_ connector.RefreshConnector  = (*ldapAggregatorConnector)(nil)
)

func (c *ldapAggregatorConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	type result struct {
		ident     connector.Identity
		validPass bool
		source    string
	}
	results := make(chan result)
	c.m.RLock()
	defer c.m.Unlock()
	var wg sync.WaitGroup
	for _, l := range c.ldapConnectors {
		wg.Add(1)
		go func(ag *ldapServer) {
			defer wg.Done()
			i, ok, err := ag.conn.Login(ctx, s, username, password)
			if err != nil {
				c.logger.Errorf("ldap-aggregator: %s: %s", l.conf.Host, err)
			}
			results <- result{i, ok, ag.conf.Host}
		}(l)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.validPass {
			var err error
			if r.ident.ConnectorData != nil {
				r.ident.ConnectorData, err = addSourceToConnectorData(r.ident.ConnectorData, r.source)
			}
			if err != nil {
				return r.ident, false, err
			}
			return r.ident, true, nil
		}
	}
	return connector.Identity{}, false, nil
}

func (c *ldapAggregatorConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var data refreshData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("ldap-aggregator: failed to unmarshal internal data: %v", err)
	}
	var a *ldapServer
	c.m.RLock()
	defer c.m.Unlock()
	for _, ac := range c.ldapConnectors {
		if ac.conf.Host == data.Source {
			a = ac
			break
		}
	}
	if a == nil {
		return ident, fmt.Errorf("ldap-aggregator: failed to find initial connector: %s", data.Source)
	}

	i, err := a.conn.Refresh(ctx, s, ident)
	if err != nil {
		return ident, fmt.Errorf("ldap-aggregator: %s", err)
	}

	i.ConnectorData, err = addSourceToConnectorData(i.ConnectorData, data.Source)
	if err != nil {
		return ident, err
	}
	return i, nil
}

func addSourceToConnectorData(data []byte, source string) ([]byte, error) {
	var d refreshData
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("ldap-aggregator: failed to unmarshal internal data: %v", err)
	}
	d.Source = source
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("ldap-aggregator: failed to marshal internal data: %v", err)
	}
	return b, nil
}

func (c *ldapAggregatorConnector) Prompt() string {
	if c.UsernamePrompt != "" {
		return c.UsernamePrompt
	}
	return "id"
}

func contains(cs []*LdapConfig, c *LdapConfig) bool {
	for _, cc := range cs {
		if cc.Host == c.Host {
			return true
		}
	}
	return false
}

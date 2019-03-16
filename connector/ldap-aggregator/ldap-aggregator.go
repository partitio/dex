// Package ldap implements strategies for authenticating using the LDAP protocol.
package ldapaggregator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/partitio/dex/connector"
	dldap "github.com/partitio/dex/connector/ldap"
	"github.com/partitio/dex/pkg/log"
	"gopkg.in/ldap.v2"
	"sync"
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
//       host: ldap.example.com:636
//       # The following field is required if using port 389.
//       # insecureNoSSL: true
//       rootCA: /etc/dex/ldap.ca
//       bindDN: uid=seviceaccount,cn=users,dc=example,dc=com
//       bindPW: password
//       userSearch:
//         # Would translate to the query "(&(objectClass=person)(uid=<username>))"
//         baseDN: cn=users,dc=example,dc=com
//         filter: "(objectClass=person)"
//         username: uid
//         idAttr: uid
//         emailAttr: mail
//         nameAttr: name
//       groupSearch:
//         # Would translate to the query "(&(objectClass=group)(member=<user uid>))"
//         baseDN: cn=groups,dc=example,dc=com
//         filter: "(objectClass=group)"
//         userAttr: uid
//         # Use if full DN is needed and not available as any other attribute
//         # Will only work if "DN" attribute does not exist in the record
//         # userAttr: DN
//         groupAttr: member
//         nameAttr: name
//
type Config struct {
	Connectors []*dldap.Config `json:"connectors"`
	// UsernamePrompt allows users to override the username attribute (displayed
	// in the username/password prompt). If unset, the handler will use
	// "Username".
	UsernamePrompt string `json:"usernamePrompt"`
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
}, error) {
	return c.openConnector(logger)
}

func (c *Config) openConnector(logger log.Logger) (*ldapConnector, error) {
	var acs []*aggregatedConnector
	for _, acc := range c.Connectors {
		ac, err := acc.OpenConnector(logger)
		if err != nil {
			logger.Errorf("invalid aggregated ldap: %s", err)
			continue
		}
		acs = append(acs, &aggregatedConnector{*acc, ac})
	}
	if len(acs) == 0 {
		return nil, errors.New("no valid aggregated connectors supplied")
	}
	return &ldapConnector{*c, acs, logger}, nil
}

type aggregatedConnector struct {
	conf dldap.Config
	conn interface {
		connector.Connector
		connector.PasswordConnector
		connector.RefreshConnector
	}
}

type ldapConnector struct {
	Config
	ldapConnectors []*aggregatedConnector
	logger         log.Logger
}

type refreshData struct {
	Username string     `json:"username"`
	Entry    ldap.Entry `json:"entry"`
	Source   string     `json:"source"`
}

var (
	_ connector.PasswordConnector = (*ldapConnector)(nil)
	_ connector.RefreshConnector  = (*ldapConnector)(nil)
)

func (c *ldapConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	type result struct {
		ident     connector.Identity
		validPass bool
		source    string
	}
	results := make(chan result)
	var wg sync.WaitGroup
	for _, l := range c.ldapConnectors {
		wg.Add(1)
		go func(ag *aggregatedConnector) {
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
			r.ident.ConnectorData, err = addSourceToConnectorData(r.ident.ConnectorData, r.source)
			if err != nil {
				return r.ident, false, err
			}
			return r.ident, true, nil
		}
	}
	return connector.Identity{}, false, nil
}

func (c *ldapConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var data refreshData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("ldap-aggregator: failed to unmarshal internal data: %v", err)
	}
	var a *aggregatedConnector
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

func (c *ldapConnector) Prompt() string {
	return c.UsernamePrompt
}

// Package ldap implements strategies for authenticating using the LDAP protocol.
package ldapaggregator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

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
//     type: ldap
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

func scopeString(i int) string {
	switch i {
	case ldap.ScopeBaseObject:
		return "base"
	case ldap.ScopeSingleLevel:
		return "one"
	case ldap.ScopeWholeSubtree:
		return "sub"
	default:
		return ""
	}
}

func parseScope(s string) (int, bool) {
	// NOTE(ericchiang): ScopeBaseObject doesn't really make sense for us because we
	// never know the user's or group's DN.
	switch s {
	case "", "sub":
		return ldap.ScopeWholeSubtree, true
	case "one":
		return ldap.ScopeSingleLevel, true
	}
	return 0, false
}

// Open returns an authentication strategy using LDAP.
func (c *LdapConfig) Open(id string, logger log.Logger) (connector.Connector, error) {
	conn, err := c.OpenConnector(logger)
	if err != nil {
		return nil, err
	}
	return connector.Connector(conn), nil
}

// OpenConnector is the same as Open but returns a type with all implemented connector interfaces.
func (c *LdapConfig) OpenConnector(logger log.Logger) (interface {
	connector.Connector
	connector.PasswordConnector
	connector.RefreshConnector
}, error) {
	return c.openConnector(logger)
}

func (c *LdapConfig) openConnector(logger log.Logger) (*ldapConnector, error) {

	requiredFields := []struct {
		name string
		val  string
	}{
		{"host", c.Host},
		{"userSearch.baseDN", c.UserSearch.BaseDN},
		{"userSearch.username", c.UserSearch.Username},
	}

	for _, field := range requiredFields {
		if field.val == "" {
			return nil, fmt.Errorf("ldap: missing required field %q", field.name)
		}
	}

	var (
		host string
		err  error
	)
	if host, _, err = net.SplitHostPort(c.Host); err != nil {
		host = c.Host
		if c.InsecureNoSSL {
			c.Host = c.Host + ":389"
		} else {
			c.Host = c.Host + ":636"
		}
	}

	tlsConfig := &tls.Config{ServerName: host, InsecureSkipVerify: c.InsecureSkipVerify}
	if c.RootCA != "" || len(c.RootCAData) != 0 {
		data := c.RootCAData
		if len(data) == 0 {
			var err error
			if data, err = ioutil.ReadFile(c.RootCA); err != nil {
				return nil, fmt.Errorf("ldap: read ca file: %v", err)
			}
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("ldap: no certs found in ca file")
		}
		tlsConfig.RootCAs = rootCAs
	}

	if c.ClientKey != "" && c.ClientCert != "" {
		cert, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("ldap: load client cert failed: %v", err)
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	userSearchScope, ok := parseScope(c.UserSearch.Scope)
	if !ok {
		return nil, fmt.Errorf("userSearch.Scope unknown value %q", c.UserSearch.Scope)
	}
	groupSearchScope, ok := parseScope(c.GroupSearch.Scope)
	if !ok {
		return nil, fmt.Errorf("groupSearch.Scope unknown value %q", c.GroupSearch.Scope)
	}
	// Organization is zero value so we set it to DN
	if c.Organization == "" {
		dnParsed := strings.Split(c.BindDN, "dc=")
		if len(dnParsed) < 2 {
			return nil, fmt.Errorf("could not retrieve organization from BindDN, bindDN must contain at least 2 dc")
		}
		// We use the second last dn (dn=example,dn=com will use example as organization name))
		c.Organization = strings.Replace(dnParsed[len(dnParsed)-2], ",", "", 1)
	}
	return &ldapConnector{*c, userSearchScope, groupSearchScope, tlsConfig, logger}, nil
}

type ldapConnector struct {
	LdapConfig

	userSearchScope  int
	groupSearchScope int

	tlsConfig *tls.Config

	logger log.Logger
}

var (
	_ connector.PasswordConnector = (*ldapConnector)(nil)
	_ connector.RefreshConnector  = (*ldapConnector)(nil)
)

// do initializes a connection to the LDAP directory and passes it to the
// provided function. It then performs appropriate teardown or reuse before
// returning.
func (c *ldapConnector) do(ctx context.Context, f func(c *ldap.Conn) error) error {
	// TODO(ericchiang): support context here
	var (
		conn *ldap.Conn
		err  error
	)
	switch {
	case c.InsecureNoSSL:
		conn, err = ldap.Dial("tcp", c.Host)
	case c.StartTLS:
		conn, err = ldap.Dial("tcp", c.Host)
		if err != nil {
			return fmt.Errorf("failed to connect: %v", err)
		}
		if err := conn.StartTLS(c.tlsConfig); err != nil {
			return fmt.Errorf("start TLS failed: %v", err)
		}
	default:
		conn, err = ldap.DialTLS("tcp", c.Host, c.tlsConfig)
	}
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// If bindDN and bindPW are empty this will default to an anonymous bind.
	if err := conn.Bind(c.BindDN, c.BindPW); err != nil {
		if c.BindDN == "" && c.BindPW == "" {
			return fmt.Errorf("ldap: initial anonymous bind failed: %v", err)
		}
		return fmt.Errorf("ldap: initial bind for user %q failed: %v", c.BindDN, err)
	}

	return f(conn)
}

func getAttrs(e ldap.Entry, name string) []string {
	for _, a := range e.Attributes {
		if a.Name != name {
			continue
		}
		return a.Values
	}
	if name == "DN" {
		return []string{e.DN}
	}
	return nil
}

func getAttr(e ldap.Entry, name string) string {
	if a := getAttrs(e, name); len(a) > 0 {
		return a[0]
	}
	return ""
}

func (c *ldapConnector) identityFromEntry(user ldap.Entry) (ident connector.Identity, err error) {
	// If we're missing any attributes, such as name or ID, we want to report
	// an error rather than continuing.
	missing := []string{}

	// Fill the identity struct using the attributes from the user entry.
	if ident.UserID = getAttr(user, c.UserSearch.IdAttr); ident.UserID == "" {
		missing = append(missing, c.UserSearch.IdAttr)
	}
	// Special case for AD objectGUID which we have to decode
	if c.UserSearch.IdAttr == "objectGUID" && ident.UserID != "" {
		var err error
		if ident.UserID, err = decodeGUID([]byte(ident.UserID)); err != nil {
			missing = append(missing, c.UserSearch.IdAttr)
		}
	}

	if c.UserSearch.NameAttr != "" {
		if ident.Username = getAttr(user, c.UserSearch.NameAttr); ident.Username == "" {
			missing = append(missing, c.UserSearch.NameAttr)
		}
	}

	if c.UserSearch.EmailSuffix != "" {
		ident.Email = ident.Username + "@" + c.UserSearch.EmailSuffix
	} else {
		ident.Email = getAttr(user, c.UserSearch.EmailAttr)
	}
	// TODO(ericchiang): Let this value be set from an attribute.
	ident.EmailVerified = true

	if len(missing) != 0 {
		err := fmt.Errorf("ldap: entry %q missing following required attribute(s): %q", user.DN, missing)
		return connector.Identity{}, err
	}
	return ident, nil
}

func (c *ldapConnector) userEntry(conn *ldap.Conn, username string) (user ldap.Entry, found bool, err error) {
	filter := fmt.Sprintf("(%s=%s)", c.UserSearch.Username, ldap.EscapeFilter(username))
	if c.UserSearch.Filter != "" {
		filter = fmt.Sprintf("(&%s%s)", c.UserSearch.Filter, filter)
	}

	// Initial search.
	req := &ldap.SearchRequest{
		BaseDN: c.UserSearch.BaseDN,
		Filter: filter,
		Scope:  c.userSearchScope,
		// We only need to search for these specific requests.
		Attributes: []string{
			c.UserSearch.IdAttr,
			c.UserSearch.EmailAttr,
			c.GroupSearch.UserAttr,
			// TODO(ericchiang): what if this contains duplicate values?
		},
	}

	if c.UserSearch.NameAttr != "" {
		req.Attributes = append(req.Attributes, c.UserSearch.NameAttr)
	}

	c.logger.Infof("performing ldap search %s %s %s",
		req.BaseDN, scopeString(req.Scope), req.Filter)
	resp, err := conn.Search(req)
	if err != nil {
		return ldap.Entry{}, false, fmt.Errorf("ldap: search with filter %q failed: %v", req.Filter, err)
	}

	switch n := len(resp.Entries); n {
	case 0:
		c.logger.Errorf("ldap: no results returned for filter: %q", filter)
		return ldap.Entry{}, false, nil
	case 1:
		user = *resp.Entries[0]
		c.logger.Infof("username %q mapped to entry %s", username, user.DN)
		return user, true, nil
	default:
		return ldap.Entry{}, false, fmt.Errorf("ldap: filter returned multiple (%d) results: %q", n, filter)
	}
}

func (c *ldapConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (ident connector.Identity, validPass bool, err error) {
	// make this check to avoid unauthenticated bind to the LDAP server.
	if password == "" {
		return connector.Identity{}, false, nil
	}

	var (
		// We want to return a different error if the user's password is incorrect vs
		// if there was an error.
		incorrectPass = false
		user          ldap.Entry
	)

	err = c.do(ctx, func(conn *ldap.Conn) error {
		entry, found, err := c.userEntry(conn, username)
		if err != nil {
			return err
		}
		if !found {
			incorrectPass = true
			return nil
		}
		user = entry

		// Try to authenticate as the distinguished name.
		if err := conn.Bind(user.DN, password); err != nil {
			// Detect a bad password through the LDAP error code.
			if ldapErr, ok := err.(*ldap.Error); ok {
				switch ldapErr.ResultCode {
				case ldap.LDAPResultInvalidCredentials:
					c.logger.Errorf("ldap: invalid password for user %q", user.DN)
					incorrectPass = true
					return nil
				case ldap.LDAPResultConstraintViolation:
					c.logger.Errorf("ldap: constraint violation for user %q: %s", user.DN, ldapErr.Error())
					incorrectPass = true
					return nil
				}
			} // will also catch all ldap.Error without a case statement above
			return fmt.Errorf("ldap: failed to bind as dn %q: %v", user.DN, err)
		}
		return nil
	})
	if err != nil {
		return connector.Identity{}, false, err
	}
	if incorrectPass {
		return connector.Identity{}, false, nil
	}

	if ident, err = c.identityFromEntry(user); err != nil {
		return connector.Identity{}, false, err
	}

	if s.Groups {
		groups, err := c.groups(ctx, user)
		if err != nil {
			return connector.Identity{}, false, fmt.Errorf("ldap: failed to query groups: %v", err)
		}
		ident.Groups = groups
	}

	if s.OfflineAccess {
		refresh := refreshData{
			Username: username,
			Entry:    user,
		}
		// Encode entry for follow up requests such as the groups query and
		// refresh attempts.
		if ident.ConnectorData, err = json.Marshal(refresh); err != nil {
			return connector.Identity{}, false, fmt.Errorf("ldap: marshal entry: %v", err)
		}
	}

	return ident, true, nil
}

func (c *ldapConnector) Refresh(ctx context.Context, s connector.Scopes, ident connector.Identity) (connector.Identity, error) {
	var data refreshData
	if err := json.Unmarshal(ident.ConnectorData, &data); err != nil {
		return ident, fmt.Errorf("ldap: failed to unmarshal internal data: %v", err)
	}

	var user ldap.Entry
	err := c.do(ctx, func(conn *ldap.Conn) error {
		entry, found, err := c.userEntry(conn, data.Username)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("ldap: user not found %q", data.Username)
		}
		user = entry
		return nil
	})
	if err != nil {
		return ident, err
	}
	if user.DN != data.Entry.DN {
		return ident, fmt.Errorf("ldap: refresh for username %q expected DN %q got %q", data.Username, data.Entry.DN, user.DN)
	}

	newIdent, err := c.identityFromEntry(user)
	if err != nil {
		return ident, err
	}
	newIdent.ConnectorData = ident.ConnectorData

	if s.Groups {
		groups, err := c.groups(ctx, user)
		if err != nil {
			return connector.Identity{}, fmt.Errorf("ldap: failed to query groups: %v", err)
		}
		newIdent.Groups = groups
	}
	return newIdent, nil
}

func decodeGUID(b []byte) (string, error) {
	reverse := func(s []byte) []byte {
		var out []byte
		for i := len(s) - 1; i >= 0; i-- {
			out = append(out, s[i])
		}
		return out
	}
	if len(b) != 16 {
		return "", errors.New("bytes length must be 16")
	}
	buf := make([]byte, 36)
	hex.Encode(buf, reverse(b[:4]))
	buf[8] = '-'
	hex.Encode(buf[9:13], reverse(b[4:6]))
	buf[13] = '-'
	hex.Encode(buf[14:18], reverse(b[6:8]))
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], b[10:])
	return string(buf), nil
}

func (c *ldapConnector) groups(ctx context.Context, user ldap.Entry) ([]string, error) {
	if c.GroupSearch.BaseDN == "" {
		c.logger.Debugf("No groups returned for %q because no groups baseDN has been configured.", getAttr(user, c.UserSearch.NameAttr))
		return nil, nil
	}

	var groups []*ldap.Entry
	for _, attr := range getAttrs(user, c.GroupSearch.UserAttr) {
		filter := fmt.Sprintf("(%s=%s)", c.GroupSearch.GroupAttr, ldap.EscapeFilter(attr))
		if c.GroupSearch.Filter != "" {
			filter = fmt.Sprintf("(&%s%s)", c.GroupSearch.Filter, filter)
		}

		req := &ldap.SearchRequest{
			BaseDN:     c.GroupSearch.BaseDN,
			Filter:     filter,
			Scope:      c.groupSearchScope,
			Attributes: []string{c.GroupSearch.NameAttr},
		}

		gotGroups := false
		if err := c.do(ctx, func(conn *ldap.Conn) error {
			c.logger.Infof("performing ldap search %s %s %s",
				req.BaseDN, scopeString(req.Scope), req.Filter)
			resp, err := conn.Search(req)
			if err != nil {
				return fmt.Errorf("ldap: search failed: %v", err)
			}
			gotGroups = len(resp.Entries) != 0
			groups = append(groups, resp.Entries...)
			return nil
		}); err != nil {
			return nil, err
		}
		if !gotGroups {
			// TODO(ericchiang): Is this going to spam the logs?
			c.logger.Errorf("ldap: groups search with filter %q returned no groups", filter)
		}
	}

	// Add the organization as a group
	groupNames := []string{c.Organization}
	for _, group := range groups {
		name := getAttr(*group, c.GroupSearch.NameAttr)
		if name == "" {
			// Be obnoxious about missing missing attributes. If the group entry is
			// missing its name attribute, that indicates a misconfiguration.
			//
			// In the future we can add configuration options to just log these errors.
			return nil, fmt.Errorf("ldap: group entity %q missing required attribute %q",
				group.DN, c.GroupSearch.NameAttr)
		}
		name = fmt.Sprintf("%s::%s", c.Organization, name)
		groupNames = append(groupNames, name)
	}
	return groupNames, nil
}

func (c *ldapConnector) Prompt() string {
	return c.UsernamePrompt
}

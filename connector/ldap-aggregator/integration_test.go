package ldapaggregator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/dexidp/dex/connector"
)

var (
	conn          *ldapAggregatorConnector
	client        LdapAggregatorClient
	dockerCompose = "connector/ldap-aggregator/testdata/docker-compose.yml"
	servers       = []struct {
		name     string
		password string
		addr     string
		endUrl   string
		users    []struct {
			username string
			password string
		}
	}{
		{
			name:     "ldap-1",
			password: "Passw1rd!",
			addr:     "127.0.0.1:1636",
			endUrl:   "com",
			users: []struct {
				username string
				password string
			}{
				{
					username: "john",
					password: "Pas$w0rd!",
				},
				{
					username: "jane",
					password: "Pas$w0rd!",
				},
			},
		},
		{
			name:     "ldap-2",
			password: "Passw2rd!",
			addr:     "127.0.0.1:2636",
			endUrl:   "net",
			users: []struct {
				username string
				password string
			}{
				{
					username: "john",
					password: "Pas$w1rd!",
				},
				{
					username: "jane",
					password: "Pas$w1rd!",
				},
			},
		},
		{
			name:     "ldap-3",
			password: "Passw3rd!",
			addr:     "127.0.0.1:3636",
			endUrl:   "org",
			users: []struct {
				username string
				password string
			}{
				{
					username: "john",
					password: "Pas$w2rd!",
				},
				{
					username: "jane",
					password: "Pas$w2rd!",
				},
			},
		},
	}
)

func Test(t *testing.T) {
	if os.Getenv(envVar) != "1" {
		t.Skipf("%s not set. Skipping test (run 'export %s=1' to run tests)", envVar, envVar)
	}
	// create docker-compose stack
	if err := prepare(); err != nil {
		t.Fatal(err)
	}
	// delete docker-compose stack when done
	defer cleanUp()

	config := Config{
		GRPC: &GRPC{
			Addr: "localhost:6666",
		},
		PassPhrase: "abcdef0123",
		Sqlite:     "integration.db",
	}
	// Cleanup DB file
	defer os.Remove("integration.db")

	c, err := config.OpenConnector(logrus.StandardLogger())
	if err != nil {
		t.Fatal(err)
	}

	conn = c.(*ldapAggregatorConnector)
	defer func() {
		if conn.grpc != nil {
			conn.grpc.GracefulStop()
		}
	}()
	grpcConn, err := grpc.Dial("localhost:6666", grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer grpcConn.Close()

	client = NewLdapAggregatorClient(grpcConn)
	t.Run("create ldap config with invalid DN for organization", testCreateConfigInvalidDN)
	t.Run("create an ldap config", testCreateConfig)
	t.Run("update ldap config", testUpdateConfig)
	t.Run("update a non-existing ldap config", testConfigNotFound)
	t.Run("read config", testReadConfig)
	t.Run("read non-existing config", testReadNonExistingConfig)
	t.Run("list all configs", testListConfig)
	t.Run("delete ldap config", testDeleteConfig)
	t.Run("delete a non-existing ldap config", testDeleteNonExistingConfig)
}

var id string

func testCreateConfigInvalidDN(t *testing.T) {
	j := servers[0]
	config := &LdapConfig{
		Host:               j.addr,
		InsecureSkipVerify: true,
		BindDN:             fmt.Sprint("cn=administrator,cn=users,=", j.endUrl),
		BindPW:             j.password,
		UsernamePrompt:     "username",
		UserSearch: &UserSearch{
			BaseDN:      fmt.Sprint("cn=users,dc=example,dc=", j.endUrl),
			Filter:      "(objectClass=user)",
			Username:    "sAMAccountName",
			IdAttr:      "objectGUID",
			EmailAttr:   "mail",
			NameAttr:    "cn",
			EmailSuffix: fmt.Sprint("example.", j.endUrl),
		},
		GroupSearch: &GroupSearch{
			BaseDN:    fmt.Sprint("cn=groups,dc=example,dc=", j.endUrl),
			Filter:    "(objectClass=group)",
			UserAttr:  "DN",
			GroupAttr: "member",
			NameAttr:  "cn",
		},
	}

	res, err := client.Create(context.Background(), &CreateRequest{Payload: config})
	require.Error(t, err)
	require.
		Nil(t, res)
}
func testCreateConfig(t *testing.T) {
	for i, j := range servers {
		config := &LdapConfig{
			Host:               j.addr,
			InsecureSkipVerify: true,
			BindDN:             fmt.Sprint("cn=administrator,cn=users,dc=example,dc=", j.endUrl),
			BindPW:             j.password,
			UsernamePrompt:     "username",
			UserSearch: &UserSearch{
				BaseDN:      fmt.Sprint("cn=users,dc=example,dc=", j.endUrl),
				Filter:      "(objectClass=user)",
				Username:    "sAMAccountName",
				IdAttr:      "objectGUID",
				EmailAttr:   "mail",
				NameAttr:    "cn",
				EmailSuffix: fmt.Sprint("example.", j.endUrl),
			},
			GroupSearch: &GroupSearch{
				BaseDN:    fmt.Sprint("cn=groups,dc=example,dc=", j.endUrl),
				Filter:    "(objectClass=group)",
				UserAttr:  "DN",
				GroupAttr: "member",
				NameAttr:  "cn",
			},
		}

		res, err := client.Create(context.Background(), &CreateRequest{Payload: config})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.False(t, res.AlreadyExists)
		assert.Equal(t, config.Host, res.Result.Host)
		assert.Equal(t, "example", res.Result.Organization)
		for _, v := range j.users {
			testLogin(t, v.username, v.password, v.username+"@example."+j.endUrl, true)
		}

		if i == 0 {
			id = res.Result.Id
		}
	}
}

func testUpdateConfig(t *testing.T) {
	for i, j := range servers {
		config := &LdapConfig{
			Host:               j.addr,
			InsecureSkipVerify: true,
			BindDN:             fmt.Sprint("cn=", j.users[0].username, ",cn=users,dc=example,dc=", j.endUrl),
			BindPW:             j.users[0].password,
			UsernamePrompt:     "username",
			UserSearch: &UserSearch{
				BaseDN:      fmt.Sprint("cn=users,dc=example,dc=", j.endUrl),
				Filter:      "(objectClass=user)",
				Username:    "sAMAccountName",
				IdAttr:      "objectGUID",
				EmailAttr:   "mail",
				NameAttr:    "cn",
				EmailSuffix: fmt.Sprint("example.", j.endUrl),
			},
			Organization: "update-organization",
			GroupSearch: &GroupSearch{
				BaseDN:    fmt.Sprint("cn=groups,dc=example,dc=", j.endUrl),
				Filter:    "(objectClass=group)",
				UserAttr:  "DN",
				GroupAttr: "member",
				NameAttr:  "cn",
			},
		}

		res, err := client.Update(context.Background(), &UpdateRequest{Payload: config})
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.False(t, res.NotFound)
		assert.Equal(t, config.BindDN, res.Result.BindDN)
		assert.Equal(t, config.Host, res.Result.Host)
		require.NotNil(t, config.UserSearch)
		assert.Equal(t, config.UserSearch.BaseDN, res.Result.UserSearch.BaseDN)
		require.NotNil(t, config.GroupSearch)
		assert.Equal(t, config.GroupSearch.BaseDN, res.Result.GroupSearch.BaseDN)
		assert.Equal(t, config.Organization, res.Result.Organization)
		for _, v := range j.users {
			testLogin(t, v.username, v.password, v.username+"@example."+j.endUrl, true)
		}

		if i == 0 {
			id = res.Result.Id
		}
	}
}

func testConfigNotFound(t *testing.T) {
	config := &LdapConfig{
		Host:               "wrong_host",
		InsecureNoSSL:      true,
		InsecureSkipVerify: true,
		StartTLS:           false,
		BindDN:             "uid=update_integration,cn=integration",
		BindPW:             "update_abcdef01234",
		UsernamePrompt:     "integration",
		UserSearch: &UserSearch{
			BaseDN:   "integration",
			Username: "integration",
			Scope:    "one",
		},
		GroupSearch: &GroupSearch{
			BaseDN: "cn=group_integration",
			Scope:  "one",
		},
	}

	_, err := client.Update(context.Background(), &UpdateRequest{Payload: config})
	require.Error(t, err)
	assert.Equal(t, "rpc error: code = Unknown desc = wrong_host not found", err.Error())
}

func testReadConfig(t *testing.T) {
	res, err := client.Read(context.Background(), &ReadRequest{Id: id})
	require.NoError(t, err)
	require.NotNil(t, res.Result)
	assert.Equal(t, "127.0.0.1:1636", res.Result.Host)
	assert.False(t, res.NotFound)
}

func testReadNonExistingConfig(t *testing.T) {
	_, err := client.Read(context.Background(), &ReadRequest{Id: "wrong_id"})
	assert.Error(t, err)
}

func testListConfig(t *testing.T) {
	res, err := client.List(context.Background(), &ListRequest{})
	require.NoError(t, err)
	require.Len(t, res.Results, 3)
	assert.Equal(t, id, res.Results[0].Id)
}

func testDeleteConfig(t *testing.T) {
	res, err := client.Delete(context.Background(), &DeleteRequest{Id: id})
	require.NoError(t, err)
	assert.False(t, res.NotFound)

	read, err := client.Read(context.Background(), &ReadRequest{Id: id})
	assert.Error(t, err)
	assert.Nil(t, read)

	testLogin(t, "john", "Pas$w0rd!", "john@example.com", false)
	testLogin(t, "jane", "Pas$w0rd!", "jane@example.com", false)
}

func testDeleteNonExistingConfig(t *testing.T) {
	_, err := client.Delete(context.Background(), &DeleteRequest{Id: "wrong_id"})
	require.Error(t, err)
	assert.Equal(t, "rpc error: code = Unknown desc = wrong_id not found", err.Error())
}

func testLogin(t *testing.T, username, password, email string, valid bool) {
	identity, ok, err := conn.Login(context.Background(), connector.Scopes{Groups: false, OfflineAccess: false}, username, password)
	require.NoError(t, err)
	assert.Equal(t, valid, ok)
	if valid {
		assert.Equal(t, username, identity.Username)
		assert.Equal(t, email, identity.Email)
	}
}

func prepare() error {
	if _, err := os.Stat(dockerCompose); os.IsNotExist(err) {
		dockerCompose = "testdata/docker-compose.yml"
	}
	wait := time.Duration(30)
	logrus.Info("Pulling docker images")
	if err := runDockerComposeCommand("pull"); err != nil {
		return err
	}
	logrus.Info("Creating docker-compose project")
	if err := runDockerComposeCommand("up", "-d"); err != nil {
		return err
	}
	// go func() {
	// 	runDockerComposeCommand("logs", "-f")
	// }()
	// Let some time to services to start
	logrus.Infof("Waiting %d seconds for services to start", wait)
	time.Sleep(wait * time.Second)
	logrus.Info("Creating users")
	if err := createUsers(); err != nil {
		return err
	}
	return nil
}

func cleanUp() {
	logrus.Info("Cleaning up")
	logrus.Info("Stopping project")
	if err := runDockerComposeCommand("down", "--volumes", "--remove-orphans"); err != nil {
		logrus.Error(err)
	}
}

func createUsers() error {
	for _, v := range servers {
		for _, vv := range v.users {
			if err := createUser(v.name, vv.username, vv.password); err != nil {
				return err
			}
		}
	}
	return nil
}

func createUser(server, username, password string) error {
	logrus.Infof("Creating user %s on %s", username, server)
	return runDockerComposeCommand("exec", "-T", server, "samba-tool", "user", "create", username, password)
}

func runDockerComposeCommand(args ...string) error {
	cmdArgs := append([]string{"-f", dockerCompose}, args...)
	cmd := exec.CommandContext(context.Background(), "docker-compose", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Wait()
}

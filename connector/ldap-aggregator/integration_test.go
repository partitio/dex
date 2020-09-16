package ldapaggregator

import (
	"context"
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
		name  string
		users []struct {
			username string
			password string
		}
	}{
		{
			name: "ldap-1",
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
			name: "ldap-2",
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
			name: "ldap-3",
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
	// if os.Getenv(envVar) != "1" {
	// 	t.Skipf("%s not set. Skipping test (run 'export %s=1' to run tests)", envVar, envVar)
	// }
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

	grpcConn, err := grpc.Dial("localhost:6666", grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer grpcConn.Close()

	client = NewLdapAggregatorClient(grpcConn)

	t.Run("create an ldap config", TestCreateConfig)
	t.Run("update ldap config", TestUpdateConfig)
	t.Run("update a non-existing ldap config", TestConfigNotFound)
	t.Run("read config", TestReadConfig)
	t.Run("read non-existing config", TestReadNonExistingConfig)
	t.Run("list all configs", TestListConfig)
	t.Run("delete ldap config", TestDeleteConfig)
	t.Run("delete a non-existing ldap config", TestDeleteNonExistingConfig)
}

var id string

func TestCreateConfig(t *testing.T) {
	config := &LdapConfig{
		Host:               "127.0.0.1:1636",
		InsecureSkipVerify: true,
		BindDN:             "cn=administrator,cn=users,dc=example,dc=com",
		BindPW:             "Passw1rd!",
		UsernamePrompt:     "username",
		UserSearch: &UserSearch{
			BaseDN:      "cn=users,dc=example,dc=com",
			Filter:      "(objectClass=user)",
			Username:    "sAMAccountName",
			IdAttr:      "objectGUID",
			EmailAttr:   "mail",
			NameAttr:    "cn",
			EmailSuffix: "example.com",
		},
		GroupSearch: &GroupSearch{
			BaseDN:    "cn=groups,dc=example,dc=com",
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

	identity, valid, err := conn.Login(context.Background(), connector.Scopes{Groups: false, OfflineAccess: false}, "john", "Pas$w0rd!")
	require.NoError(t, err)
	require.True(t, valid)
	require.NotNil(t, identity)
	assert.Equal(t, "john", identity.Username)

	id = res.Result.Id
}

func TestUpdateConfig(t *testing.T) {
	config := &LdapConfig{
		Host:               "127.0.0.1:1636",
		InsecureSkipVerify: true,
		BindDN:             "cn=john,cn=users,dc=example,dc=com",
		BindPW:             "Pas$w0rd!",
		UsernamePrompt:     "username",
		UserSearch: &UserSearch{
			BaseDN:      "cn=users,dc=example,dc=com",
			Filter:      "(objectClass=user)",
			Username:    "sAMAccountName",
			IdAttr:      "objectGUID",
			EmailAttr:   "mail",
			NameAttr:    "cn",
			EmailSuffix: "example.com",
		},
		GroupSearch: &GroupSearch{
			BaseDN:    "cn=groups,dc=example,dc=com",
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

	identity, valid, err := conn.Login(context.Background(), connector.Scopes{Groups: false, OfflineAccess: false}, "john", "Pas$w0rd!")
	require.NoError(t, err)
	require.True(t, valid)
	require.NotNil(t, identity)
	assert.Equal(t, "john", identity.Username)

	id = res.Result.Id
}

func TestConfigNotFound(t *testing.T) {
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

func TestReadConfig(t *testing.T) {
	res, err := client.Read(context.Background(), &ReadRequest{Id: id})
	require.NoError(t, err)
	require.NotNil(t, res.Result)
	assert.Equal(t, "127.0.0.1:1636", res.Result.Host)
	assert.False(t, res.NotFound)
}

func TestReadNonExistingConfig(t *testing.T) {
	_, err := client.Read(context.Background(), &ReadRequest{Id: "wrong_id"})
	assert.Error(t, err)
}

func TestListConfig(t *testing.T) {
	res, err := client.List(context.Background(), &ListRequest{})
	require.NoError(t, err)
	require.Len(t, res.Results, 1)
	assert.Equal(t, id, res.Results[0].Id)
}

func TestDeleteConfig(t *testing.T) {
	res, err := client.Delete(context.Background(), &DeleteRequest{Id: id})
	require.NoError(t, err)
	assert.False(t, res.NotFound)

	read, err := client.Read(context.Background(), &ReadRequest{Id: id})
	assert.Error(t, err)
	assert.Nil(t, read)

	identity, valid, err := conn.Login(context.Background(), connector.Scopes{Groups: false, OfflineAccess: false}, "john", "Pas$w0rd!")
	// require.NoError(t, err)
	require.False(t, valid)
	assert.NotEqual(t, "john", identity.Username)
}

func TestDeleteNonExistingConfig(t *testing.T) {
	_, err := client.Delete(context.Background(), &DeleteRequest{Id: "wrong_id"})
	require.Error(t, err)
	assert.Equal(t, "rpc error: code = Unknown desc = wrong_id not found", err.Error())
}

func prepare() error {
	if _, err := os.Stat(dockerCompose); os.IsNotExist(err) {
		dockerCompose = "testdata/docker-compose.yml"
	}
	wait := time.Duration(15)
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

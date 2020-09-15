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
)

var (
	dockerCompose = "connector/ldap-aggregator/testdata/docker-compose.yml"
)

func TestEmptyConfig(t *testing.T) {
	emptyConfig := &Config{}
	c, err := emptyConfig.Open("", logrus.New())
	assert.Error(t, err)
	assert.Nil(t, c)
}

func TestConfigNoAPINoServers(t *testing.T) {
	emptyConfig := &Config{
		GRPC:       nil,
		Postgres:   nil,
		Sqlite:     ":memory:",
		PassPhrase: "dsoihv6çc*%",
		Servers:    nil,
	}
	c, err := emptyConfig.Open("", logrus.New())
	assert.Error(t, err)
	assert.Nil(t, c)
}

func TestServer(t *testing.T) {
	addr := "0.0.0.0:9090"
	config := &Config{
		GRPC: &GRPC{
			Addr: addr,
		},
		Postgres:   nil,
		Sqlite:     ":memory:",
		PassPhrase: "some-passphrase-68QDSHOUQQC°%$",
		Servers:    nil,
	}
	c, err := config.Open("", logrus.New())
	require.NoError(t, err)
	require.NotNil(t, c)
	s, ok := c.(*ldapAggregatorConnector)
	require.True(t, ok)
	assert.Empty(t, s.Servers)
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cl := NewLdapAggregatorClient(conn)

	lr, err := cl.List(context.Background(), &ListRequest{})
	require.NoError(t, err)
	require.NotNil(t, lr)
	assert.Empty(t, lr.Results)
	cr, err := cl.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{}})
	assert.Error(t, err)
	assert.Nil(t, cr)
}

var (
	servers = []struct {
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

func TestLdapAggregator(t *testing.T) {
	if os.Getenv(envVar) != "1" {
		t.Skipf("%s not set. Skipping test (run 'export %s=1' to run tests)", envVar, envVar)
	}
	// create docker-compose stack
	if err := prepare(); err != nil {
		t.Fatal(err)
	}
	// delete docker-compose stack when done
	defer cleanUp()

	// TODO(antoine): write tests
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
	go func() {
		runDockerComposeCommand("logs", "-f")
	}()
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

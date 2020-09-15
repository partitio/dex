package integration

import (
	"context"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	ldapaggregator "github.com/dexidp/dex/connector/ldap-aggregator"
)

var client ldapaggregator.LdapAggregatorClient

func Test(t *testing.T) {
	config := ldapaggregator.Config{
		GRPC: &ldapaggregator.GRPC{
			Addr: "localhost:6666",
		},
		UsernamePrompt: "integration",
		PassPhrase:     "abcdef0123",
		Sqlite:         "integration.db",
	}
	// Cleanup DB file
	defer os.Remove("integration.db")

	_, err := config.OpenConnector(logrus.StandardLogger())
	if err != nil {
		t.Fatal(err)
	}

	conn, err := grpc.Dial("localhost:6666", grpc.WithInsecure())
	defer conn.Close()
	if err != nil {
		t.Fatal(err)
	}

	client = ldapaggregator.NewLdapAggregatorClient(conn)

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
	config := &ldapaggregator.LdapConfig{
		Host:               "localhost:389",
		InsecureNoSSL:      true,
		InsecureSkipVerify: true,
		StartTLS:           false,
		BindDN:             "uid=create_integration,cn=integration",
		BindPW:             "abcdef01234",
		UsernamePrompt:     "integration",
		UserSearch: &ldapaggregator.UserSearch{
			BaseDN:   "integration",
			Username: "integration",
			Scope:    "one",
		},
		GroupSearch: &ldapaggregator.GroupSearch{
			BaseDN: "cn=group_integration",
			Scope:  "one",
		},
	}

	res, err := client.Create(context.Background(), &ldapaggregator.CreateRequest{Payload: config})
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.False(t, res.AlreadyExists)
	assert.Equal(t, config.Host, res.Result.Host)

	id = res.Result.Id
}

func TestUpdateConfig(t *testing.T) {
	config := &ldapaggregator.LdapConfig{
		Host:               "localhost:389",
		InsecureNoSSL:      true,
		InsecureSkipVerify: true,
		StartTLS:           false,
		BindDN:             "uid=update_integration,cn=integration",
		BindPW:             "update_abcdef01234",
		UsernamePrompt:     "integration",
		UserSearch: &ldapaggregator.UserSearch{
			BaseDN:   "integration",
			Username: "integration",
			Scope:    "one",
		},
		GroupSearch: &ldapaggregator.GroupSearch{
			BaseDN: "cn=group_integration",
			Scope:  "one",
		},
	}

	res, err := client.Update(context.Background(), &ldapaggregator.UpdateRequest{Payload: config})
	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.False(t, res.NotFound)
	assert.Equal(t, config.BindDN, res.Result.BindDN)
	assert.Equal(t, config.Host, res.Result.Host)
	assert.Equal(t, config.UserSearch.BaseDN, res.Result.UserSearch.BaseDN)
	assert.Equal(t, config.GroupSearch.BaseDN, res.Result.GroupSearch.BaseDN)

	id = res.Result.Id
}

func TestConfigNotFound(t *testing.T) {
	config := &ldapaggregator.LdapConfig{
		Host:               "wrong_host",
		InsecureNoSSL:      true,
		InsecureSkipVerify: true,
		StartTLS:           false,
		BindDN:             "uid=update_integration,cn=integration",
		BindPW:             "update_abcdef01234",
		UsernamePrompt:     "integration",
		UserSearch: &ldapaggregator.UserSearch{
			BaseDN:   "integration",
			Username: "integration",
			Scope:    "one",
		},
		GroupSearch: &ldapaggregator.GroupSearch{
			BaseDN: "cn=group_integration",
			Scope:  "one",
		},
	}

	_, err := client.Update(context.Background(), &ldapaggregator.UpdateRequest{Payload: config})
	assert.Error(t, err)
	assert.Equal(t, "rpc error: code = Unknown desc = wrong_host not found", err.Error())
}

func TestReadConfig(t *testing.T) {
	res, err := client.Read(context.Background(), &ldapaggregator.ReadRequest{Id: id})
	require.NoError(t, err)
	assert.NotNil(t, res.Result)
	assert.Equal(t, "localhost:389", res.Result.Host)
	assert.False(t, res.NotFound)
}

func TestReadNonExistingConfig(t *testing.T) {
	_, err := client.Read(context.Background(), &ldapaggregator.ReadRequest{Id: "wrong_id"})
	assert.Error(t, err)
}

func TestListConfig(t *testing.T) {
	res, err := client.List(context.Background(), &ldapaggregator.ListRequest{})
	require.NoError(t, err)
	assert.Len(t, res.Results, 1)
	assert.Equal(t, id, res.Results[0].Id)
}

func TestDeleteConfig(t *testing.T) {
	res, err := client.Delete(context.Background(), &ldapaggregator.DeleteRequest{Id: id})
	require.NoError(t, err)
	assert.False(t, res.NotFound)

	read, err := client.Read(context.Background(), &ldapaggregator.ReadRequest{Id: id})
	assert.Error(t, err)
	assert.Nil(t, read)
}

func TestDeleteNonExistingConfig(t *testing.T) {
	_, err := client.Delete(context.Background(), &ldapaggregator.DeleteRequest{Id: "wrong_id"})
	assert.Error(t, err)
	assert.Equal(t, "rpc error: code = Unknown desc = wrong_id not found", err.Error())
}

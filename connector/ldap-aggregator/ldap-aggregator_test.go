package ldapaggregator

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

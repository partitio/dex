package ldapaggregator

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunServer(t *testing.T) {
	var conn *ldapAggregatorConnector

	tests := []struct {
		name    string
		fn      func(*testing.T)
		srvStop bool
	}{
		{
			name: "run server w/ TLS",
			fn: func(t *testing.T) {
				err := conn.Run()
				assert.NoError(t, err)
			},
			srvStop: true,
		},
		{
			name: "run server w TLS",
			fn: func(t *testing.T) {
				conn.GRPC.TLSCert = "ca.crt"
				conn.GRPC.TLSKey = "ca.key"

				err := conn.Run()
				assert.NoError(t, err)
			},
			srvStop: true,
		},
		{
			name: "ldap aggregator API is disabled",
			fn: func(t *testing.T) {
				conn.GRPC = nil
				err := conn.Run()
				// TODO: Not useful, change it
				assert.Nil(t, err)
			},
			srvStop: false,
		},
	}

	for _, test := range tests {
		// Reset the grpc server
		conn = &ldapAggregatorConnector{
			Config: Config{
				GRPC: &GRPC{
					Addr: "localhost:6666",
				},
			},
			ldapConnectors:              []*ldapServer{},
			logger:                      logrus.StandardLogger(),
			m:                           sync.RWMutex{},
			grpc:                        nil, // conn.Run() will store value in it
			LdapAggregatorDefaultServer: &LdapAggregatorDefaultServer{},
		}

		t.Run(test.name, test.fn)

		if test.srvStop {
			conn.grpc.GracefulStop()
		}
	}
}

func TestCreateLdap(t *testing.T) {
	dbname := "test_create_config.db"
	var conn *ldapAggregatorConnector
	db, err := gorm.Open("sqlite3", dbname)
	require.NoError(t, err)
	assert.NotNil(t, db)

	err = db.AutoMigrate(&LdapConfigORM{}).Error
	require.NoError(t, err)
	db = db.Set("gorm:auto_preload", true)

	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{
			name: "create a ldap config",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host:               "localhost",
					RootCA:             "testdata/ca.crt",
					InsecureNoSSL:      false,
					InsecureSkipVerify: false,
					ClientCert:         "testdata/client.crt",
					ClientKey:          "testdata/client.key",
					UserSearch: &UserSearch{
						BaseDN:   "default",
						Username: "default_username",
						Scope:    "one",
					},
					GroupSearch: &GroupSearch{Scope: "one"},
				}})
				require.NoError(t, err)
				assert.NotNil(t, res)

				listRes, err := conn.List(context.Background(), &ListRequest{})
				assert.NoError(t, err)
				assert.NotNil(t, listRes)
				assert.Len(t, listRes.Results, 1)
			},
		},
		{
			name: "failed to open a connector without required fields",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host: "",
					UserSearch: &UserSearch{
						BaseDN:   "",
						Username: "",
					},
				}})
				assert.Error(t, err)
				assert.Equal(t, "ldap: missing required field \"host\"", err.Error())
				assert.Nil(t, res)
			},
		},
		{
			name: "failed to open a connector with a wrong root CA",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host:   "localhost",
					RootCA: "./wrong_file.ca",
					UserSearch: &UserSearch{
						BaseDN:   "default",
						Username: "default_username",
					},
				}})
				assert.Nil(t, res)
				assert.Error(t, err)
			},
		},
		{
			name: "failed to open a connector with wrong root CA data",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host:       "localhost",
					RootCAData: []byte{00, 11},
					UserSearch: &UserSearch{
						BaseDN:   "default",
						Username: "default_username",
					},
				}})
				assert.Nil(t, res)
				assert.Error(t, err)
				assert.Equal(t, "ldap: no certs found in ca file", err.Error())
			},
		},
		{
			name: "failed to open a connector with wrong client CA",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host:       "localhost",
					RootCA:     "testdata/ca.crt",
					ClientCert: "testdata/wrong_client.crt",
					ClientKey:  "testdata/wrong_client.key",
					UserSearch: &UserSearch{
						BaseDN:   "default",
						Username: "default_username",
					},
				}})
				assert.Nil(t, res)
				assert.Error(t, err)
			},
		},
		{
			name: "failed to open a connector with no user search scope",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host:       "localhost",
					RootCA:     "testdata/ca.crt",
					ClientCert: "testdata/client.crt",
					ClientKey:  "testdata/client.key",
					UserSearch: &UserSearch{
						BaseDN:   "default",
						Username: "default_username",
						Scope:    "wrong user scope",
					},
				}})
				assert.Nil(t, res)
				assert.Error(t, err)
				assert.Equal(t, "userSearch.Scope unknown value \"wrong user scope\"", err.Error())
			},
		},
		{
			name: "failed to open a connector with no group search scope",
			fn: func(t *testing.T) {
				res, err := conn.Create(context.Background(), &CreateRequest{Payload: &LdapConfig{
					Host:       "localhost",
					RootCA:     "testdata/ca.crt",
					ClientCert: "testdata/client.crt",
					ClientKey:  "testdata/client.key",
					UserSearch: &UserSearch{
						BaseDN:   "default",
						Username: "default_username",
						Scope:    "one",
					},
					GroupSearch: &GroupSearch{
						Scope: "wrong group scope",
					},
				}})
				assert.Nil(t, res)
				assert.Error(t, err)
				assert.Equal(t, "groupSearch.Scope unknown value \"wrong group scope\"", err.Error())
			},
		},
		// TODO: Why is already exist not in result ?
		// {
		// 	name: "create an already existing ldap server",
		// 	fn: func(t *testing.T) {
		// 		ldapConfig := &LdapConfig{
		// 			Id: "some id",
		// 		}
		//
		// 		res, err := conn.Create(context.Background(), &CreateRequest{Payload: ldapConfig})
		// 		require.NoError(t, err)
		// 		assert.NotNil(t, res)
		//
		// 		res, err = conn.Create(context.Background(), &CreateRequest{Payload: ldapConfig})
		// 		require.NoError(t, err)
		// 		assert.NotNil(t, res)
		// 		assert.True(t, res.AlreadyExists)
		// 	},
		// },
	}

	for _, test := range tests {
		// Reset the grpc server
		conn = &ldapAggregatorConnector{
			Config: Config{
				GRPC: &GRPC{
					Addr: "localhost:6666",
				},
			},
			ldapConnectors:              []*ldapServer{},
			logger:                      logrus.StandardLogger(),
			m:                           sync.RWMutex{},
			grpc:                        nil, // Run will store value in it
			LdapAggregatorDefaultServer: &LdapAggregatorDefaultServer{DB: db},
		}

		err = conn.Run()
		require.NoError(t, err)

		t.Run(test.name, test.fn)
		conn.grpc.GracefulStop()
	}

	os.Remove(dbname)
}

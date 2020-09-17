package ldapaggregator

import (
	"context"
	"os"
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
		name string
		fn   func(*testing.T)
	}{
		{
			name: "run server w/ TLS",
			fn: func(t *testing.T) {
				err := conn.Run()
				assert.NoError(t, err)
			},
		},
		{
			name: "run server w TLS",
			fn: func(t *testing.T) {
				conn.GRPC.TLSCert = "testdata/ca.crt"
				conn.GRPC.TLSKey = "testdata/ca.key"

				err := conn.Run()
				assert.NoError(t, err)
			},
		},
		{
			name: "ldap aggregator API is disabled",
			fn: func(t *testing.T) {
				conn.GRPC = nil
				err := conn.Run()
				// TODO: Not useful, change it
				assert.Nil(t, err)
			},
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
			logger:                          logrus.StandardLogger(),
			LdapAggregatorDefaultGRPCServer: &LdapAggregatorDefaultGRPCServer{},
		}

		t.Run(test.name, test.fn)

		if conn.grpc != nil {
			conn.grpc.GracefulStop()
		}
	}
}

func TestCreateLdap(t *testing.T) {
	dbname := "test_create_config.db"
	db, err := gorm.Open("sqlite3", dbname)
	require.NoError(t, err)
	defer os.Remove(dbname)
	assert.NotNil(t, db)

	err = db.AutoMigrate(&LdapConfigORM{}).Error
	require.NoError(t, err)
	db = db.Set("gorm:auto_preload", true)

	conn := &ldapAggregatorConnector{
		Config: Config{
			GRPC: &GRPC{
				Addr: "localhost:6666",
			},
		},
		logger:                          logrus.StandardLogger(),
		LdapAggregatorDefaultGRPCServer: NewLdapAggregatorDefaultGRPCServer(db),
	}
	err = conn.Run()
	require.NoError(t, err)

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

		t.Run(test.name, test.fn)
	}

	conn.grpc.GracefulStop()
}

func TestReadLdap(t *testing.T) {
	dbname := "test_read_config.db"
	db, err := gorm.Open("sqlite3", dbname)
	require.NoError(t, err)
	defer os.Remove(dbname)
	assert.NotNil(t, db)

	err = db.AutoMigrate(&LdapConfigORM{}).Error
	require.NoError(t, err)
	db = db.Set("gorm:auto_preload", true)

	conn := &ldapAggregatorConnector{
		Config: Config{
			GRPC: &GRPC{
				Addr: "localhost:6666",
			},
		},
		logger:                          logrus.StandardLogger(),
		LdapAggregatorDefaultGRPCServer: NewLdapAggregatorDefaultGRPCServer(db),
	}

	err = conn.Run()
	require.NoError(t, err)

	test := func(t *testing.T) {
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

		readRes, err := conn.Read(context.Background(), &ReadRequest{Id: res.Result.Id})
		assert.NoError(t, err)
		assert.NotNil(t, readRes)
	}

	t.Run("Read existing config", test)

	conn.grpc.GracefulStop()
}

func TestUpdateLdap(t *testing.T) {
	dbname := "test_update_config.db"
	db, err := gorm.Open("sqlite3", dbname)
	require.NoError(t, err)
	defer os.Remove(dbname)
	assert.NotNil(t, db)

	err = db.AutoMigrate(&LdapConfigORM{}).Error
	require.NoError(t, err)
	db = db.Set("gorm:auto_preload", true)

	conn := &ldapAggregatorConnector{
		Config: Config{
			GRPC: &GRPC{
				Addr: "localhost:6666",
			},
		},
		logger:                          logrus.StandardLogger(),
		LdapAggregatorDefaultGRPCServer: NewLdapAggregatorDefaultGRPCServer(db),
	}

	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{
			name: "Update an existing ldap config",
			fn: func(t *testing.T) {
				ldapConfig := &LdapConfig{
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
				}

				res, err := conn.Create(context.Background(), &CreateRequest{Payload: ldapConfig})
				require.NoError(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, ldapConfig.Host, res.Result.Id)

				ldapConfig = res.Result

				ldapConfig.InsecureSkipVerify = true
				ldapConfig.InsecureNoSSL = true

				updateRes, err := conn.Update(context.Background(), &UpdateRequest{Payload: ldapConfig})
				assert.NoError(t, err)
				assert.NotNil(t, updateRes)

				listRes, err := conn.List(context.Background(), &ListRequest{})
				require.NoError(t, err)
				assert.True(t, listRes.Results[0].InsecureSkipVerify)
				assert.True(t, listRes.Results[0].InsecureNoSSL)
			},
		},
		{
			name: "try update a non existing config",
			fn: func(t *testing.T) {
				ldapConfig := &LdapConfig{
					Host:               "Invalid host",
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
				}

				resUpdate, err := conn.Update(context.Background(), &UpdateRequest{Payload: ldapConfig})
				require.Error(t, err)
				require.NotNil(t, resUpdate)
				assert.True(t, resUpdate.NotFound)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, test.fn)
	}

}

func TestDeleteLdap(t *testing.T) {
	dbname := "test_delete_config.db"
	db, err := gorm.Open("sqlite3", dbname)
	require.NoError(t, err)
	defer os.Remove(dbname)
	assert.NotNil(t, db)

	err = db.AutoMigrate(&LdapConfigORM{}).Error
	require.NoError(t, err)

	conn := &ldapAggregatorConnector{
		Config: Config{
			GRPC: &GRPC{
				Addr: "localhost:6666",
			},
		},
		logger:                          logrus.StandardLogger(),
		LdapAggregatorDefaultGRPCServer: NewLdapAggregatorDefaultGRPCServer(db),
	}

	tests := []struct {
		name string
		fn   func(*testing.T)
	}{
		{
			name: "Delete an existing ldap config",
			fn: func(t *testing.T) {
				ldapConfig := &LdapConfig{
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
				}

				res, err := conn.Create(context.Background(), &CreateRequest{Payload: ldapConfig})
				require.NoError(t, err)
				assert.NotNil(t, res)
				ldapConfig = res.Result

				updateRes, err := conn.Delete(context.Background(), &DeleteRequest{Id: ldapConfig.Id})
				assert.NoError(t, err)
				assert.NotNil(t, updateRes)

				listRes, err := conn.List(context.Background(), &ListRequest{})
				assert.NoError(t, err)
				assert.Len(t, listRes.Results, 0)
			},
		},
		{
			name: "try delete a non existing config",
			fn: func(t *testing.T) {
				res, err := conn.Delete(context.Background(), &DeleteRequest{Id: "invalid"})
				require.Error(t, err)
				assert.True(t, res.NotFound)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, test.fn)
	}

}

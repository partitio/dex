package dex

import (
	"testing"

	"github.com/dexidp/dex/connector/mock"
	"github.com/dexidp/dex/server"
	"github.com/dexidp/dex/storage/sql"
)

func TestRegisterConnector(t *testing.T) {
	err := RegisterConnector("name", nil)
	if err == nil {
		t.Error("register connector: got no error, empty config parser should fails")
	}
	err = RegisterConnector("ldap", func() server.ConnectorConfig {
		return server.ConnectorConfig(nil)
	})
	if err == nil {
		t.Error("register connector: got no error, pre defined connectors names should raise an error")
	}
	err = RegisterConnector("mock_connector", func() server.ConnectorConfig {
		return new(mock.CallbackConfig)
	})
	if err != nil {
		t.Errorf("register connector: got an unexpected error : %s", err)
	}
	testConfig.Storage = Storage{
		Type: "sqlite",
		Config: &sql.SQLite3{
			File: ":memory:",
		},
	}
	testConfig.StaticConnectors = append(testConfig.StaticConnectors, Connector{
		Name:   "new_mock",
		Type:   "mock_connector",
		ID:     "new_mock",
		Config: new(mock.CallbackConfig),
	})
	_, err = New(testConfig)
	if err != nil {
		t.Errorf("initialize dex: got an unexpected error : %s", err)
	}
}

package sql

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/partitio/dex/pkg/log"
	"github.com/partitio/dex/storage"
	"github.com/partitio/dex/storage/conformance"
	"github.com/sirupsen/logrus"
)

func withTimeout(t time.Duration, f func()) {
	c := make(chan struct{})
	defer close(c)

	go func() {
		select {
		case <-c:
		case <-time.After(t):
			// Dump a stack trace of the program. Useful for debugging deadlocks.
			buf := make([]byte, 2<<20)
			fmt.Fprintf(os.Stderr, "%s\n", buf[:runtime.Stack(buf, true)])
			panic("test took too long")
		}
	}()

	f()
}

func cleanDB(c *conn) error {
	tables := []string{"client", "auth_request", "auth_code",
		"refresh_token", "keys", "password"}

	for _, tbl := range tables {
		_, err := c.Exec("delete from " + tbl)
		if err != nil {
			return err
		}
	}
	return nil
}

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

type opener interface {
	open(logger log.Logger) (*conn, error)
}

func testDB(t *testing.T, o opener, withTransactions bool) {
	// t.Fatal has a bad habbit of not actually printing the error
	fatal := func(i interface{}) {
		fmt.Fprintln(os.Stdout, i)
		t.Fatal(i)
	}

	newStorage := func() storage.Storage {
		conn, err := o.open(logger)
		if err != nil {
			fatal(err)
		}
		if err := cleanDB(conn); err != nil {
			fatal(err)
		}
		return conn
	}
	withTimeout(time.Minute*1, func() {
		conformance.RunTests(t, newStorage)
	})
	if withTransactions {
		withTimeout(time.Minute*1, func() {
			conformance.RunTransactionTests(t, newStorage)
		})
	}
}

func TestSQLite3(t *testing.T) {
	testDB(t, &SQLite3{":memory:"}, false)
}

func getenv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

const testPostgresEnv = "DEX_POSTGRES_HOST"

func TestCreateDataSourceName(t *testing.T) {
	var testCases = []struct {
		description string
		input       *Postgres
		expected    string
	}{
		{
			description: "with no configuration",
			input:       &Postgres{},
			expected:    "connect_timeout=0 sslmode='verify-full'",
		},
		{
			description: "with typical configuration",
			input: &Postgres{
				Host:     "1.2.3.4",
				Port:     6543,
				User:     "some-user",
				Password: "some-password",
				Database: "some-db",
			},
			expected: "connect_timeout=0 host='1.2.3.4' port=6543 user='some-user' password='some-password' dbname='some-db' sslmode='verify-full'",
		},
		{
			description: "with unix socket host",
			input: &Postgres{
				Host: "/var/run/postgres",
				SSL: SSL{
					Mode: "disable",
				},
			},
			expected: "connect_timeout=0 host='/var/run/postgres' sslmode='disable'",
		},
		{
			description: "with tcp host",
			input: &Postgres{
				Host: "coreos.com",
				SSL: SSL{
					Mode: "disable",
				},
			},
			expected: "connect_timeout=0 host='coreos.com' sslmode='disable'",
		},
		{
			description: "with tcp host:port",
			input: &Postgres{
				Host: "coreos.com:6543",
			},
			expected: "connect_timeout=0 host='coreos.com' port=6543 sslmode='verify-full'",
		},
		{
			description: "with tcp host and port",
			input: &Postgres{
				Host: "coreos.com",
				Port: 6543,
			},
			expected: "connect_timeout=0 host='coreos.com' port=6543 sslmode='verify-full'",
		},
		{
			description: "with ssl ca cert",
			input: &Postgres{
				Host: "coreos.com",
				SSL: SSL{
					Mode:   "verify-ca",
					CAFile: "/some/file/path",
				},
			},
			expected: "connect_timeout=0 host='coreos.com' sslmode='verify-ca' sslrootcert='/some/file/path'",
		},
		{
			description: "with ssl client cert",
			input: &Postgres{
				Host: "coreos.com",
				SSL: SSL{
					Mode:     "verify-ca",
					CAFile:   "/some/ca/path",
					CertFile: "/some/cert/path",
					KeyFile:  "/some/key/path",
				},
			},
			expected: "connect_timeout=0 host='coreos.com' sslmode='verify-ca' sslrootcert='/some/ca/path' sslcert='/some/cert/path' sslkey='/some/key/path'",
		},
		{
			description: "with funny characters in credentials",
			input: &Postgres{
				Host:     "coreos.com",
				User:     `some'user\slashed`,
				Password: "some'password!",
			},
			expected: `connect_timeout=0 host='coreos.com' user='some\'user\\slashed' password='some\'password!' sslmode='verify-full'`,
		},
	}

	var actual string
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			actual = testCase.input.createDataSourceName()

			if actual != testCase.expected {
				t.Fatalf("%s != %s", actual, testCase.expected)
			}
		})
	}
}

func TestPostgres(t *testing.T) {
	host := os.Getenv(testPostgresEnv)
	if host == "" {
		t.Skipf("test environment variable %q not set, skipping", testPostgresEnv)
	}
	p := &Postgres{
		NetworkDB: NetworkDB{
			Database:          getenv("DEX_POSTGRES_DATABASE", "postgres"),
			User:              getenv("DEX_POSTGRES_USER", "postgres"),
			Password:          getenv("DEX_POSTGRES_PASSWORD", "postgres"),
			Host:              host,
			ConnectionTimeout: 5,
		},
		SSL: SSL{
			Mode: pgSSLDisable, // Postgres container doesn't support SSL.
		},
	}
	testDB(t, p, true)
}

const testMySQLEnv = "DEX_MYSQL_HOST"

func TestMySQL(t *testing.T) {
	host := os.Getenv(testMySQLEnv)
	if host == "" {
		t.Skipf("test environment variable %q not set, skipping", testMySQLEnv)
	}
	s := &MySQL{
		NetworkDB: NetworkDB{
			Database:          getenv("DEX_MYSQL_DATABASE", "mysql"),
			User:              getenv("DEX_MYSQL_USER", "mysql"),
			Password:          getenv("DEX_MYSQL_PASSWORD", ""),
			Host:              host,
			ConnectionTimeout: 5,
		},
		SSL: SSL{
			Mode: mysqlSSLFalse,
		},
		params: map[string]string{
			"innodb_lock_wait_timeout": "3",
		},
	}
	testDB(t, s, true)
}

package postgresql

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/blang/semver"
	"github.com/elliotchance/sshtunnel"
	_ "github.com/lib/pq" // PostgreSQL db
	"gocloud.dev/postgres"
	_ "gocloud.dev/postgres/awspostgres"
	_ "gocloud.dev/postgres/gcppostgres"
	"golang.org/x/crypto/ssh"
)

type featureName uint

const (
	featureCreateRoleWith featureName = iota
	featureDatabaseOwnerRole
	featureDBAllowConnections
	featureDBIsTemplate
	featureFallbackApplicationName
	featureRLS
	featureSchemaCreateIfNotExist
	featureReplication
	featureExtension
	featurePrivileges
	featureProcedure
	featureRoutine
	featurePrivilegesOnSchemas
	featureForceDropDatabase
	featurePid
	featurePublishViaRoot
	featurePubTruncate
	featurePublication
	featurePubWithoutTruncate
	featureFunction
	featureServer
)

var (
	dbRegistryLock sync.Mutex
	dbRegistry     map[string]*DBConnection = make(map[string]*DBConnection, 1)

	// Mapping of feature flags to versions
	featureSupported = map[featureName]semver.Range{
		// CREATE ROLE WITH
		featureCreateRoleWith: semver.MustParseRange(">=8.1.0"),

		// CREATE DATABASE has ALLOW_CONNECTIONS support
		featureDBAllowConnections: semver.MustParseRange(">=9.5.0"),

		// CREATE DATABASE has IS_TEMPLATE support
		featureDBIsTemplate: semver.MustParseRange(">=9.5.0"),

		// https://www.postgresql.org/docs/9.0/static/libpq-connect.html
		featureFallbackApplicationName: semver.MustParseRange(">=9.0.0"),

		// CREATE SCHEMA IF NOT EXISTS
		featureSchemaCreateIfNotExist: semver.MustParseRange(">=9.3.0"),

		// row-level security
		featureRLS: semver.MustParseRange(">=9.5.0"),

		// CREATE ROLE has REPLICATION support.
		featureReplication: semver.MustParseRange(">=9.1.0"),

		// CREATE EXTENSION support.
		featureExtension: semver.MustParseRange(">=9.1.0"),

		// We do not support postgresql_grant and postgresql_default_privileges
		// for Postgresql < 9.
		featurePrivileges: semver.MustParseRange(">=9.0.0"),

		// Object PROCEDURE support
		featureProcedure: semver.MustParseRange(">=11.0.0"),

		// Object ROUTINE support
		featureRoutine: semver.MustParseRange(">=11.0.0"),
		// ALTER DEFAULT PRIVILEGES has ON SCHEMAS support
		// for Postgresql >= 10
		featurePrivilegesOnSchemas: semver.MustParseRange(">=10.0.0"),

		// DROP DATABASE WITH FORCE
		// for Postgresql >= 13
		featureForceDropDatabase: semver.MustParseRange(">=13.0.0"),

		// Column procpid was replaced by pid in pg_stat_activity
		// for Postgresql >= 9.2 and above
		featurePid: semver.MustParseRange(">=9.2.0"),

		// attribute publish_via_partition_root for partition is supported
		featurePublishViaRoot: semver.MustParseRange(">=13.0.0"),

		// attribute pubtruncate for publications is supported
		featurePubTruncate: semver.MustParseRange(">=11.0.0"),

		// attribute pubtruncate for publications is supported
		featurePubWithoutTruncate: semver.MustParseRange("<11.0.0"),

		// publication is Supported
		featurePublication: semver.MustParseRange(">=10.0.0"),

		// We do not support CREATE FUNCTION for Postgresql < 8.4
		featureFunction: semver.MustParseRange(">=8.4.0"),
		// CREATE SERVER support
		featureServer: semver.MustParseRange(">=10.0.0"),

		featureDatabaseOwnerRole: semver.MustParseRange(">=15.0.0"),
	}
)

type DBConnection struct {
	*sql.DB

	client *Client

	// version is the version number of the database as determined by parsing the
	// output of `SELECT VERSION()`.x
	version semver.Version
}

// featureSupported returns true if a given feature is supported or not. This is
// slightly different from Config's featureSupported in that here we're
// evaluating against the fingerprinted version, not the expected version.
func (db *DBConnection) featureSupported(name featureName) bool {
	fn, found := featureSupported[name]
	if !found {
		// panic'ing because this is a provider-only bug
		panic(fmt.Sprintf("unknown feature flag %v", name))
	}

	return fn(db.version)
}

// isSuperuser returns true if connected user is a Postgres SUPERUSER
func (db *DBConnection) isSuperuser() (bool, error) {
	var superuser bool

	if err := db.QueryRow("SELECT rolsuper FROM pg_roles WHERE rolname = CURRENT_USER").Scan(&superuser); err != nil {
		return false, fmt.Errorf("could not check if current user is superuser: %w", err)
	}

	return superuser, nil
}

type ClientCertificateConfig struct {
	CertificatePath string
	KeyPath         string
	SSLInline       bool
}

type SSHTunnelConfig struct {
	Destination string
	UseAgent    bool
	Password    string
	PrivateKey  string
	LocalPort   int
}

// Config - provider config
type Config struct {
	Scheme            string
	Host              string
	Port              int
	Username          string
	Password          string
	DatabaseUsername  string
	Superuser         bool
	SSLMode           string
	ApplicationName   string
	Timeout           int
	ConnectTimeoutSec int
	MaxConns          int
	ExpectedVersion   semver.Version
	SSLClientCert     *ClientCertificateConfig
	SSLRootCertPath   string
	SSHTunnel         *SSHTunnelConfig
}

// Client struct holding connection string
type Client struct {
	// Configuration for the client
	config Config

	databaseName string

	tunnel *sshtunnel.SSHTunnel
}

// NewClient returns client config for the specified database.
func (c *Config) NewClient(database string) *Client {
	return &Client{
		config:       *c,
		databaseName: database,
	}
}

// featureSupported returns true if a given feature is supported or not.  This
// is slightly different from Client's featureSupported in that here we're
// evaluating against the expected version, not the fingerprinted version.
func (c *Config) featureSupported(name featureName) bool {
	fn, found := featureSupported[name]
	if !found {
		// panic'ing because this is a provider-only bug
		panic(fmt.Sprintf("unknown feature flag %v", name))
	}

	return fn(c.ExpectedVersion)
}

func (c *Config) connParams() []string {
	params := map[string]string{}

	// sslmode and connect_timeout are not allowed with gocloud
	// (TLS is provided by gocloud directly)
	if c.Scheme == "postgres" {
		params["sslmode"] = c.SSLMode
		params["connect_timeout"] = strconv.Itoa(c.ConnectTimeoutSec)
	}

	if c.featureSupported(featureFallbackApplicationName) {
		params["fallback_application_name"] = c.ApplicationName
	}
	if c.SSLClientCert != nil {
		params["sslcert"] = c.SSLClientCert.CertificatePath
		params["sslkey"] = c.SSLClientCert.KeyPath
		if c.SSLClientCert.SSLInline {
			params["sslinline"] = strconv.FormatBool(c.SSLClientCert.SSLInline)
		}
	}

	if c.SSLRootCertPath != "" {
		params["sslrootcert"] = c.SSLRootCertPath
	}

	paramsArray := []string{}
	for key, value := range params {
		paramsArray = append(paramsArray, fmt.Sprintf("%s=%s", key, url.QueryEscape(value)))
	}

	return paramsArray
}

func (c *Config) connStr(database string) string {
	host := c.Host
	port := c.Port
	// For GCP, support both project/region/instance and project:region:instance
	// (The second one allows to use the output of google_sql_database_instance as host
	if c.Scheme == "gcppostgres" {
		host = strings.ReplaceAll(host, ":", "/")
	}

	if c.Scheme == "gcpalloydb" {
		connStr := fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
			host,
			url.PathEscape(c.Username),
			url.PathEscape(c.Password),
			database)
		return connStr
	}

	if c.SSHTunnel != nil {
		host = "127.0.0.1"
		port = c.SSHTunnel.LocalPort
	}

	connStr := fmt.Sprintf(
		"%s://%s:%s@%s:%d/%s?%s",
		c.Scheme,
		url.PathEscape(c.Username),
		url.PathEscape(c.Password),
		host,
		port,
		database,
		strings.Join(c.connParams(), "&"),
	)

	return connStr
}

func (c *Config) getDatabaseUsername() string {
	if c.DatabaseUsername != "" {
		return c.DatabaseUsername
	}
	return c.Username
}

// Connect returns a copy to an sql.Open()'ed database connection wrapped in a DBConnection struct.
// Callers must return their database resources. Use of QueryRow() or Exec() is encouraged.
// Query() must have their rows.Close()'ed.
func (c *Client) Connect() (*DBConnection, error) {
	dbRegistryLock.Lock()
	defer dbRegistryLock.Unlock()

	if c.config.SSHTunnel != nil && c.tunnel == nil {
		var auth ssh.AuthMethod
		switch {
		case c.config.SSHTunnel.UseAgent:
			auth = sshtunnel.SSHAgent()
		case c.config.SSHTunnel.Password != "":
			auth = ssh.Password(c.config.SSHTunnel.Password)
		case c.config.SSHTunnel.PrivateKey != "":
			key, err := ssh.ParsePrivateKey([]byte(c.config.SSHTunnel.PrivateKey))
			if err != nil {
				return nil, fmt.Errorf("error while parsing ssh private key: %+v", err)
			}
			auth = ssh.PublicKeys(key)
		default:
			return nil, fmt.Errorf("error while authenticing to ssh dest: you must choose one of 'use_agent', 'password', 'private_key'")
		}

		tunnel, err := sshtunnel.NewSSHTunnel(
			c.config.SSHTunnel.Destination,
			auth,
			fmt.Sprintf("%s:%d", c.config.Host, c.config.Port),
			"0",
		)

		if err != nil {
			return nil, fmt.Errorf("error while opening ssh tunnel: %+v", err)
		}

		go func() {
			err := tunnel.Start()
			if err != nil {
				panic(fmt.Sprintf("unable to start ssh tunnel %+v", err))
			}
			defer tunnel.Close()
		}()

		time.Sleep(100 * time.Millisecond)

		c.config.SSHTunnel.LocalPort = tunnel.Local.Port
		c.tunnel = tunnel

	}

	dsn := c.config.connStr(c.databaseName)
	conn, found := dbRegistry[dsn]
	if !found {

		var db *sql.DB
		var err error
		switch c.config.Scheme {
		case "postgres":
			if c.tunnel != nil {
				db, err = sql.Open(c.config.Scheme, dsn)
			} else {
				db, err = sql.Open(proxyDriverName, dsn)
			}
		case "gcpalloydb":
			db, err = sql.Open(c.config.Scheme, dsn)
		default:
			db, err = postgres.Open(context.Background(), dsn)
		}

		if err == nil {
			err = db.Ping()
		}
		if err != nil {
			errString := strings.Replace(err.Error(), c.config.Password, "XXXX", 2)
			return nil, fmt.Errorf("Error connecting to PostgreSQL server %s (scheme: %s): %s", c.config.Host, c.config.Scheme, errString)
		}

		// We don't want to retain connection
		// So when we connect on a specific database which might be managed by terraform,
		// we don't keep opened connection in case of the db has to be dopped in the plan.
		db.SetMaxIdleConns(0)
		db.SetMaxOpenConns(c.config.MaxConns)

		defaultVersion, _ := semver.Parse(defaultExpectedPostgreSQLVersion)
		version := &c.config.ExpectedVersion
		if defaultVersion.Equals(c.config.ExpectedVersion) {
			// Version hint not set by user, need to fingerprint
			version, err = fingerprintCapabilities(db)
			if err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("error detecting capabilities: %w", err)
			}
		}

		conn = &DBConnection{
			db,
			c,
			*version,
		}
		dbRegistry[dsn] = conn
	}

	return conn, nil
}

// fingerprintCapabilities queries PostgreSQL to populate a local catalog of
// capabilities.  This is only run once per Client.
func fingerprintCapabilities(db *sql.DB) (*semver.Version, error) {
	var pgVersion string
	err := db.QueryRow(`SELECT VERSION()`).Scan(&pgVersion)
	if err != nil {
		return nil, fmt.Errorf("error PostgreSQL version: %w", err)
	}

	// PostgreSQL 9.2.21 on x86_64-apple-darwin16.5.0, compiled by Apple LLVM version 8.1.0 (clang-802.0.42), 64-bit
	// PostgreSQL 9.6.7, compiled by Visual C++ build 1800, 64-bit
	fields := strings.FieldsFunc(pgVersion, func(c rune) bool {
		return unicode.IsSpace(c) || c == ','
	})
	if len(fields) < 2 {
		return nil, fmt.Errorf("error determining the server version: %q", pgVersion)
	}

	version, err := semver.ParseTolerant(fields[1])
	if err != nil {
		return nil, fmt.Errorf("error parsing version: %w", err)
	}

	return &version, nil
}

package etc

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"time"

	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/caarlos0/env/v6"
	log "github.com/sirupsen/logrus"
)

var version = "Unknown"
var once sync.Once

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API        API
	AquaCSP    AquaCSP
	RedisStore RedisStore
	RedisPool  RedisPool
}

type API struct {
	Addr           string        `env:"SCANNER_API_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_TLS_KEY"`
	ReadTimeout    time.Duration `env:"SCANNER_API_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_IDLE_TIMEOUT" envDefault:"60s"`
}

func (c API) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type ImageRegistration string

const (
	Never     ImageRegistration = "Never"
	Always    ImageRegistration = "Always"
	Compliant ImageRegistration = "Compliant"
)

type AquaCSP struct {
	Username string `env:"SCANNER_AQUA_USERNAME"`
	Password string `env:"SCANNER_AQUA_PASSWORD"`
	Host     string `env:"SCANNER_AQUA_HOST" envDefault:"http://csp-console-svc.aqua:8080"`
	Registry string `env:"SCANNER_AQUA_REGISTRY" envDefault:"Harbor"`

	UseImageTag              bool              `env:"SCANNER_AQUA_USE_IMAGE_TAG" envDefault:"true"`
	ReportsDir               string            `env:"SCANNER_AQUA_REPORTS_DIR" envDefault:"/var/lib/scanner/reports"`
	ScannerCLINoVerify       bool              `env:"SCANNER_CLI_NO_VERIFY" envDefault:"false"`
	ScannerCLIShowNegligible bool              `env:"SCANNER_CLI_SHOW_NEGLIGIBLE" envDefault:"true"`
	ScannerCLIDirectCC       bool              `env:"SCANNER_CLI_DIRECT_CC" envDefault:"false"`
	ScannerCLIRegisterImages ImageRegistration `env:"SCANNER_CLI_REGISTER_IMAGES" envDefault:"Never"`

	ScannerCLIOverrideRegistryCredentials bool `env:"SCANNER_CLI_OVERRIDE_REGISTRY_CREDENTIALS" envDefault:"false"`

	ReportDelete bool `env:"SCANNER_AQUA_REPORT_DELETE" envDefault:"true"`
}

type RedisStore struct {
	Namespace  string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.aqua:store"`
	ScanJobTTL time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

type RedisPool struct {
	URL               string        `env:"SCANNER_REDIS_URL" envDefault:"redis://harbor-harbor-redis:6379"`
	MaxActive         int           `env:"SCANNER_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	MaxIdle           int           `env:"SCANNER_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	IdleTimeout       time.Duration `env:"SCANNER_REDIS_POOL_IDLE_TIMEOUT" envDefault:"5m"`
	ConnectionTimeout time.Duration `env:"SCANNER_REDIS_POOL_CONNECTION_TIMEOUT" envDefault:"1s"`
	ReadTimeout       time.Duration `env:"SCANNER_REDIS_POOL_READ_TIMEOUT" envDefault:"1s"`
	WriteTimeout      time.Duration `env:"SCANNER_REDIS_POOL_WRITE_TIMEOUT" envDefault:"1s"`
}

var (
	customParser = map[reflect.Type]env.ParserFunc{
		reflect.TypeOf(ImageRegistration("")): func(v string) (interface{}, error) {
			switch v {
			case string(Never):
				return Never, nil
			case string(Always):
				return Always, nil
			case string(Compliant):
				return Compliant, nil
			}
			return nil, fmt.Errorf("expected values %s, %s or %s but got %s", Never, Always, Compliant, v)
		},
	}
)

func GetConfig() (Config, error) {
	var cfg Config
	err := env.ParseWithFuncs(&cfg, customParser)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

func GetLogLevel() log.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		level, err := log.ParseLevel(value)
		if err != nil {
			return log.InfoLevel
		}
		return level
	}
	return log.InfoLevel
}

func GetScannerMetadata() harbor.Scanner {
	once.Do(func() {
		v, err := getVersion()
		if err != nil {
			log.WithError(err).Error("Error while retrieving version")
			return
		}
		version = v
	})
	return harbor.Scanner{
		Name:    "Aqua Enterprise",
		Vendor:  "Aqua Security",
		Version: version,
	}
}

func getVersion() (string, error) {
	executable, err := exec.LookPath("scannercli")
	if err != nil {
		return "", err
	}
	cmd := exec.Command(executable, "version")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

package etc

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"os"
	"os/exec"
	"sync"
	"time"
)

var version = "Unknown"
var once sync.Once

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API     API
	AquaCSP AquaCSP
	Store   Store
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

type AquaCSP struct {
	User        string `env:"SCANNER_AQUA_USER"`
	Password    string `env:"SCANNER_AQUA_PASSWORD"`
	Host        string `env:"SCANNER_AQUA_HOST" envDefault:"http://aqua-web.aqua-security:8080"`
	Registry    string `env:"SCANNER_AQUA_REGISTRY" envDefault:"Harbor"`
	ReportsDir  string `env:"SCANNER_AQUA_REPORTS_DIR" envDefault:"/var/lib/scanner/reports"`
	UseImageTag bool   `env:"SCANNER_AQUA_USE_IMAGE_TAG" envDefault:"true"`
}

type Store struct {
	RedisURL      string        `env:"SCANNER_STORE_REDIS_URL" envDefault:"redis://harbor-harbor-redis:6379"`
	Namespace     string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.aqua:store"`
	PoolMaxActive int           `env:"SCANNER_STORE_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	PoolMaxIdle   int           `env:"SCANNER_STORE_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	ScanJobTTL    time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

func GetConfig() (cfg Config, err error) {
	err = env.Parse(&cfg)
	if err != nil {
		return cfg, xerrors.Errorf("parsing config: %w", err)
	}
	return
}

func GetLogLevel() logrus.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		level, err := logrus.ParseLevel(value)
		if err != nil {
			return logrus.InfoLevel
		}
		return level
	}
	return logrus.InfoLevel
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
		Name:    "Aqua CSP Scanner",
		Vendor:  "Aqua Security",
		Version: version,
	}
}

func getVersion() (version string, err error) {
	executable, err := exec.LookPath("scannercli")
	if err != nil {
		return
	}
	cmd := exec.Command(executable, "version")
	out, err := cmd.Output()
	if err != nil {
		return
	}

	version = string(out)
	return
}

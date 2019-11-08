package etc

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

type Config struct {
	API API
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

func GetConfig() (cfg Config, err error) {
	err = env.Parse(&cfg)
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
	return harbor.Scanner{
		Name:    "Aqua CSP Scanner",
		Vendor:  "Aqua Security",
		Version: "Unknown",
	}
}

package etc

import (
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type envs map[string]string

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           envs
		expectedError  string
		expectedConfig Config
	}{
		{
			name: "Should return default config",
			expectedConfig: Config{
				API: API{
					Addr:         ":8080",
					ReadTimeout:  parseDuration(t, "15s"),
					WriteTimeout: parseDuration(t, "15s"),
					IdleTimeout:  parseDuration(t, "60s"),
				},
				AquaCSP: AquaCSP{
					Username:    "",
					Password:    "",
					Host:        "http://csp-console-svc.aqua:8080",
					Registry:    "Harbor",
					ReportsDir:  "/var/lib/scanner/reports",
					UseImageTag: true,

					ScannerCLINoVerify:                    false,
					ScannerCLIShowNegligible:              true,
					ScannerCLIOverrideRegistryCredentials: false,
					ScannerCLIRegisterImages:              Never,

					ReportDelete: true,
				},
				RedisStore: RedisStore{
					Namespace:  "harbor.scanner.aqua:store",
					ScanJobTTL: parseDuration(t, "1h"),
				},
				RedisPool: RedisPool{
					URL:               "redis://harbor-harbor-redis:6379",
					MaxActive:         5,
					MaxIdle:           5,
					IdleTimeout:       parseDuration(t, "5m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
			},
		},
		{
			name: "Should return error when ScannerCLIRegisterImages has invalid value",
			envs: envs{
				"SCANNER_CLI_REGISTER_IMAGES": "XXX",
			},
			expectedError: "env: parse error on field \"ScannerCLIRegisterImages\" of type \"etc.ImageRegistration\": expected values Never, Always or Compliant but got XXX",
		},
		{
			name: "Should overwrite default config with environment variables",
			envs: envs{
				"SCANNER_API_ADDR":                          ":4200",
				"SCANNER_API_TLS_CERTIFICATE":               "/certs/tls.crt",
				"SCANNER_API_TLS_KEY":                       "/certs/tls.key",
				"SCANNER_API_READ_TIMEOUT":                  "1h",
				"SCANNER_API_WRITE_TIMEOUT":                 "2m",
				"SCANNER_API_IDLE_TIMEOUT":                  "1h2m3s",
				"SCANNER_AQUA_REPORTS_DIR":                  "/somewhere/else",
				"SCANNER_AQUA_USE_IMAGE_TAG":                "false",
				"SCANNER_AQUA_HOST":                         "http://aqua-web.aqua-security:8080",
				"SCANNER_AQUA_USERNAME":                     "scanner",
				"SCANNER_AQUA_PASSWORD":                     "s3cret",
				"SCANNER_CLI_NO_VERIFY":                     "true",
				"SCANNER_CLI_SHOW_NEGLIGIBLE":               "false",
				"SCANNER_CLI_REGISTER_IMAGES":               "Compliant",
				"SCANNER_CLI_OVERRIDE_REGISTRY_CREDENTIALS": "true",
				"SCANNER_REDIS_URL":                         "redis://localhost:6379",
			},
			expectedConfig: Config{
				API: API{
					Addr:           ":4200",
					TLSCertificate: "/certs/tls.crt",
					TLSKey:         "/certs/tls.key",
					ReadTimeout:    parseDuration(t, "1h"),
					WriteTimeout:   parseDuration(t, "2m"),
					IdleTimeout:    parseDuration(t, "1h2m3s"),
				},
				AquaCSP: AquaCSP{
					Username:                              "scanner",
					Password:                              "s3cret",
					Host:                                  "http://aqua-web.aqua-security:8080",
					Registry:                              "Harbor",
					ReportsDir:                            "/somewhere/else",
					UseImageTag:                           false,
					ScannerCLINoVerify:                    true,
					ScannerCLIShowNegligible:              false,
					ScannerCLIRegisterImages:              Compliant,
					ScannerCLIOverrideRegistryCredentials: true,
					ReportDelete:                          true,
				},
				RedisStore: RedisStore{
					Namespace:  "harbor.scanner.aqua:store",
					ScanJobTTL: parseDuration(t, "1h"),
				},
				RedisPool: RedisPool{
					URL:               "redis://localhost:6379",
					MaxActive:         5,
					MaxIdle:           5,
					IdleTimeout:       parseDuration(t, "5m"),
					ConnectionTimeout: parseDuration(t, "1s"),
					ReadTimeout:       parseDuration(t, "1s"),
					WriteTimeout:      parseDuration(t, "1s"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			config, err := GetConfig()
			if tc.expectedError == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedConfig, config)
			} else {
				assert.EqualError(t, err, tc.expectedError)
			}
		})
	}
}

func TestGetLogLevel(t *testing.T) {
	testCases := []struct {
		name             string
		envs             envs
		expectedLogLevel logrus.Level
	}{
		{
			name:             "Should return default log level when env is not set",
			expectedLogLevel: logrus.InfoLevel,
		},
		{
			name:             "Should return default log level when env has invalid value",
			envs:             envs{"SCANNER_LOG_LEVEL": "unknown_level"},
			expectedLogLevel: logrus.InfoLevel,
		},
		{
			name:             "Should return log level set as env",
			envs:             envs{"SCANNER_LOG_LEVEL": "trace"},
			expectedLogLevel: logrus.TraceLevel,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			assert.Equal(t, tc.expectedLogLevel, GetLogLevel())
		})
	}
}

func setenvs(t *testing.T, envs envs) {
	t.Helper()
	os.Clearenv()
	for k, v := range envs {
		err := os.Setenv(k, v)
		require.NoError(t, err)
	}
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(s)
	require.NoError(t, err)
	return duration
}

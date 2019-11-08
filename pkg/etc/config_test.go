package etc

import (
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

type envs map[string]string

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           envs
		expectedError  error
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
			},
		},
		{
			name: "Should overwrite default config with environment variables",
			envs: envs{
				"SCANNER_API_ADDR":            ":4200",
				"SCANNER_API_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_TLS_KEY":         "/certs/tls.key",
				"SCANNER_API_READ_TIMEOUT":    "1h",
				"SCANNER_API_WRITE_TIMEOUT":   "2m",
				"SCANNER_API_IDLE_TIMEOUT":    "1h2m3s",
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
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			config, err := GetConfig()
			assert.Equal(t, tc.expectedError, err)
			assert.Equal(t, tc.expectedConfig, config)
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

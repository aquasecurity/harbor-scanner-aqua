package v1

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/persistence/mock"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {

	buildInfo := etc.BuildInfo{Version: "v0.0.5", Commit: "abc", Date: "20-04-1319T13:45:00"}
	config, err := etc.GetConfig()
	require.NoError(t, err)
	enqueuer := &scanner.MockEnqueuer{}
	store := &mock.Store{}
	handler := NewAPIHandler(buildInfo, config, enqueuer, store)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	t.Run("GET /api/v1/metadata", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/api/v1/metadata")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)

		bodyBytes, err := ioutil.ReadAll(rs.Body)
		require.NoError(t, err)

		assert.JSONEq(t, `{
  "scanner": {
    "name": "Aqua CSP Scanner",
    "vendor": "Aqua Security",
    "version": "Unknown"
  },
  "capabilities": [
    {
      "consumes_mime_types": [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json"
      ],
      "produces_mime_types": [
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
      ]
    }
  ],
  "properties": {
    "harbor.scanner-adapter/scanner-type": "os-package-vulnerability",

    "org.label-schema.version":    "v0.0.5",
    "org.label-schema.build-date": "20-04-1319T13:45:00",
    "org.label-schema.vcs-ref":    "abc",
    "org.label-schema.vcs":        "https://github.com/aquasecurity/harbor-scanner-aqua",

    "env.SCANNER_AQUA_HOST":             "http://csp-console-svc.aqua:8080",
    "env.SCANNER_AQUA_REGISTRY":         "Harbor",
    "env.SCANNER_AQUA_REPORTS_DIR":      "/var/lib/scanner/reports",
    "env.SCANNER_AQUA_USE_IMAGE_TAG":    "true",
    "env.SCANNER_CLI_NO_VERIFY":         "false",
    "env.SCANNER_CLI_SHOW_NEGLIGIBLE":   "true",
    "env.SCANNER_CLI_SHOW_WILL_NOT_FIX": "false",
    "env.SCANNER_CLI_HIDE_BASE":         "true"
  }
}`, string(bodyBytes))
	})

	t.Run("GET /probe/healthy", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/probe/healthy")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})

	t.Run("GET /probe/ready", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/probe/ready")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})

	t.Run("GET /metrics", func(t *testing.T) {
		rs, err := ts.Client().Get(ts.URL + "/metrics")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rs.StatusCode)
	})
}

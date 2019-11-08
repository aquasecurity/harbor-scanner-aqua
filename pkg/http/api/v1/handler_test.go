package v1

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	handler := NewAPIHandler(etc.BuildInfo{Version: "v0.0.5", Commit: "abc", Date: "20-04-1319T13:45:00"})

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
    "org.label-schema.version": "v0.0.5",
    "org.label-schema.build-date": "20-04-1319T13:45:00",
    "org.label-schema.vcs-ref": "abc",
    "org.label-schema.vcs": "https://github.com/aquasecurity/harbor-scanner-aqua"
  }
}`, string(bodyBytes))
	})

}

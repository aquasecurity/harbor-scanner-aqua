package v1

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type handler struct {
	info etc.BuildInfo
	api.BaseHandler
}

func NewAPIHandler(info etc.BuildInfo) http.Handler {
	handler := &handler{
		info: info,
	}

	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.getMetadata)

	return router
}

func (h *handler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(log.Fields{
			"remote_addr": r.RemoteAddr,
			"proto":       r.Proto,
			"method":      r.Method,
			"request_uri": r.URL.RequestURI(),
		}).Trace("Handling request")
		next.ServeHTTP(w, r)
	})
}

func (h *handler) getMetadata(res http.ResponseWriter, req *http.Request) {
	metadata := &harbor.ScannerAdapterMetadata{
		Scanner: etc.GetScannerMetadata(),
		Capabilities: []harbor.Capability{
			{
				ConsumesMIMETypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerImageManifest.String(),
				},
				ProducesMIMETypes: []string{
					api.MimeTypeHarborVulnerabilityReport.String(),
				},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type": "os-package-vulnerability",
			"org.label-schema.version":            h.info.Version,
			"org.label-schema.build-date":         h.info.Date,
			"org.label-schema.vcs-ref":            h.info.Commit,
			"org.label-schema.vcs":                "https://github.com/aquasecurity/harbor-scanner-aqua",
		},
	}
	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

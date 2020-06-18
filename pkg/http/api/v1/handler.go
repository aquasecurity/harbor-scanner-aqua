package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/job"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/scanner"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

const (
	pathVarScanRequestID = "scan_request_id"
)

type handler struct {
	info   etc.BuildInfo
	config etc.Config
	api.BaseHandler

	enqueuer scanner.Enqueuer
	store    persistence.Store
}

func NewAPIHandler(info etc.BuildInfo, config etc.Config, enqueuer scanner.Enqueuer, store persistence.Store) http.Handler {
	handler := &handler{
		info:     info,
		config:   config,
		enqueuer: enqueuer,
		store:    store,
	}

	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()

	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.getMetadata)
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.acceptScanRequest)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.getScanReport)

	probeRouter := router.PathPrefix("/probe").Subrouter()
	probeRouter.Methods(http.MethodGet).Path("/healthy").HandlerFunc(handler.getHealthy)
	probeRouter.Methods(http.MethodGet).Path("/ready").HandlerFunc(handler.getReady)

	router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())

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

func (h *handler) acceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while unmarshalling scan request")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshalling scan request: %s", err.Error()),
		})
		return
	}

	if validationError := h.validate(scanRequest); validationError != nil {
		log.Errorf("Error while validating scan request: %s", validationError.Message)
		h.WriteJSONError(res, *validationError)
		return
	}

	jobID, err := h.enqueuer.Enqueue(scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while enqueueing scan request")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueueing scan request: %s", err.Error()),
		})
		return
	}

	h.WriteJSON(res, harbor.ScanResponse{ID: jobID}, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *handler) validate(req harbor.ScanRequest) *harbor.Error {
	if req.Registry.URL == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry.url",
		}
	}

	_, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry.url",
		}
	}

	if req.Artifact.Repository == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.repository",
		}
	}

	if req.Artifact.Digest == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.digest",
		}
	}

	return nil
}

func (h *handler) getScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	jobID, ok := vars[pathVarScanRequestID]
	if !ok {
		log.Error("Error while parsing `scan_request_id` path variable")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing scan_request_id",
		})
		return
	}

	reqLog := log.WithField("scan_job_id", jobID)

	scanJob, err := h.store.Get(jobID)
	if err != nil {
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan job: %v", err),
		})
		return
	}

	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusNotFound,
			Message:  fmt.Sprintf("cannot find scan job: %v", jobID),
		})
		return
	}

	if scanJob.Status == job.Pending || scanJob.Status == job.Running {
		reqLog.WithField("scan_job_status", scanJob.Status.String()).Debug("Scan job has not finished yet")
		res.Header().Add("Location", req.URL.String())
		res.WriteHeader(http.StatusFound)
		return
	}

	if scanJob.Status == job.Failed {
		reqLog.WithField(log.ErrorKey, scanJob.Error).Error("Scan job failed")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  scanJob.Error,
		})
		return
	}

	if scanJob.Status != job.Finished {
		reqLog.WithField("scan_job_status", scanJob.Status).Error("Unexpected scan job status")
		h.WriteJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.ID),
		})
		return
	}

	h.WriteJSON(res, scanJob.Report, api.MimeTypeScanReport, http.StatusOK)
}

func (h *handler) getMetadata(res http.ResponseWriter, _ *http.Request) {
	metadata := harbor.ScannerAdapterMetadata{
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
			"env.SCANNER_AQUA_HOST":               h.config.AquaCSP.Host,
			"env.SCANNER_AQUA_REGISTRY":           h.config.AquaCSP.Registry,
			"env.SCANNER_AQUA_REPORTS_DIR":        h.config.AquaCSP.ReportsDir,
			"env.SCANNER_AQUA_USE_IMAGE_TAG":      strconv.FormatBool(h.config.AquaCSP.UseImageTag),
			"env.SCANNER_CLI_NO_VERIFY":           strconv.FormatBool(h.config.AquaCSP.ScannerCLINoVerify),
		},
	}
	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

func (h *handler) getHealthy(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *handler) getReady(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)
}

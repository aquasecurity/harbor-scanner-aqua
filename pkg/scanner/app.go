package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api"
	v1 "github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"os"
	"os/signal"
	"syscall"
)

func Run(info etc.BuildInfo) error {
	log.WithFields(log.Fields{
		"version":  info.Version,
		"commit":   info.Version,
		"built_at": info.Date,
	}).Info("Starting harbor-scanner-aqua")

	config, err := etc.GetConfig()
	if err != nil {
		return xerrors.Errorf("getting config: %w", err)
	}

	apiServer := api.NewServer(config.API, v1.NewAPIHandler(info))

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		log.WithField("signal", captured.String()).Debug("Trapped os signal")

		apiServer.Shutdown()

		close(shutdownComplete)
	}()

	apiServer.ListenAndServe()

	<-shutdownComplete
	return nil
}

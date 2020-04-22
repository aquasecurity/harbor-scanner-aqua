package pkg

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/scanner"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/work"
	log "github.com/sirupsen/logrus"
)

func Run(info etc.BuildInfo) error {
	log.WithFields(log.Fields{
		"version":  info.Version,
		"commit":   info.Commit,
		"built_at": info.Date,
	}).Info("Starting harbor-scanner-aqua")

	config, err := etc.GetConfig()
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	if _, err := os.Stat(config.AquaCSP.ReportsDir); os.IsNotExist(err) {
		log.WithField("path", config.AquaCSP.ReportsDir).Debug("Creating reports dir")
		err = os.MkdirAll(config.AquaCSP.ReportsDir, os.ModeDir)
		if err != nil {
			return fmt.Errorf("creating reports dir: %w", err)
		}
	}

	workPool := work.New()
	command := aqua.NewCommand(config.AquaCSP, ext.DefaultAmbassador)
	transformer := scanner.NewTransformer(ext.NewSystemClock())
	adapter := scanner.NewAdapter(command, transformer)
	store := redis.NewStore(config.Store)
	enqueuer := scanner.NewEnqueuer(workPool, adapter, store)
	apiServer := api.NewServer(config.API, v1.NewAPIHandler(info, enqueuer, store))

	shutdownComplete := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, syscall.SIGINT, syscall.SIGTERM)
		captured := <-sigint
		log.WithField("signal", captured.String()).Debug("Trapped os signal")

		apiServer.Shutdown()
		workPool.Shutdown()

		close(shutdownComplete)
	}()

	workPool.Start()
	apiServer.ListenAndServe()

	<-shutdownComplete
	return nil
}

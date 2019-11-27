package pkg

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/clock"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/scanner"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/work"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"os"
	"os/signal"
	"syscall"
)

func Run(info etc.BuildInfo) error {
	log.WithFields(log.Fields{
		"version":  info.Version,
		"commit":   info.Commit,
		"built_at": info.Date,
	}).Info("Starting harbor-scanner-aqua")

	config, err := etc.GetConfig()
	if err != nil {
		return xerrors.Errorf("getting config: %w", err)
	}

	workPool := work.New()
	command := aqua.NewCommand(config.AquaCSP)
	transformer := scanner.NewTransformer(clock.NewSystemClock())
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

package main

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/scanner"
	log "github.com/sirupsen/logrus"
	"os"
)

var (
	// Default wise GoReleaser sets three ldflags:
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(etc.GetLogLevel())
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})

	info := etc.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	if err := scanner.Run(info); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

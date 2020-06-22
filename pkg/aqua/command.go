package aqua

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/ext"
	log "github.com/sirupsen/logrus"
)

type ImageRef struct {
	Repository string
	Tag        string
	Digest     string
	Auth       RegistryAuth
}

type RegistryAuth struct {
	Username string
	Password string
}

func (ir *ImageRef) WithTag() string {
	return fmt.Sprintf("%s:%s", ir.Repository, ir.Tag)
}

func (ir *ImageRef) WithDigest() string {
	return fmt.Sprintf("%s@%s", ir.Repository, ir.Digest)
}

// Command represents the CLI interface for the Aqua CSP scanner,
// i.e. scannercli executable.
type Command interface {
	Scan(imageRef ImageRef) (ScanReport, error)
}

// NewCommands constructs Aqua CSP scanner command with the given configuration.
func NewCommand(cfg etc.AquaCSP, ambassador ext.Ambassador) Command {
	return &command{
		cfg:        cfg,
		ambassador: ambassador,
	}
}

type command struct {
	cfg        etc.AquaCSP
	ambassador ext.Ambassador
}

func (c *command) Scan(imageRef ImageRef) (report ScanReport, err error) {
	executable, err := c.ambassador.LookPath("scannercli")
	if err != nil {
		return report, fmt.Errorf("searching for scannercli executable: %w", err)
	}
	reportFile, err := c.ambassador.TempFile(c.cfg.ReportsDir, "aqua_scan_report_*.json")
	if err != nil {
		return report, fmt.Errorf("creating tmp scan report file: %w", err)
	}
	log.WithField("path", reportFile.Name()).Debug("Saving tmp scan report file")
	defer func() {
		log.WithField("path", reportFile.Name()).Debug("Removing tmp scan report file")
		err := c.ambassador.Remove(reportFile.Name())
		if err != nil {
			log.WithError(err).Warn("Error while removing tmp scan report file")
		}
	}()

	image := imageRef.WithDigest()
	if c.cfg.UseImageTag {
		image = imageRef.WithTag()
	}

	args := []string{
		"scan",
		"--checkonly",
		"--dockerless",
		fmt.Sprintf("--user=%s", c.cfg.Username),
		fmt.Sprintf("--host=%s", c.cfg.Host),
		fmt.Sprintf("--registry=%s", c.cfg.Registry),
		fmt.Sprintf("--no-verify=%t", c.cfg.ScannerCLINoVerify),
		fmt.Sprintf("--show-negligible=%t", c.cfg.ScannerCLIShowNegligible),
		fmt.Sprintf("--jsonfile=%s", reportFile.Name()),
	}

	log.WithFields(log.Fields{"exec": executable, "args": args}).Debug("Running scannercli")

	if c.cfg.ScannerCLIOverrideRegistryCredentials {
		args = append(args, fmt.Sprintf("--robot-username=%s", imageRef.Auth.Username),
			fmt.Sprintf("--robot-password=%s", imageRef.Auth.Password))
	}
	args = append(args, fmt.Sprintf("--password=%s", c.cfg.Password), image)

	cmd := exec.Command(executable, args...)

	stdout, exitCode, err := c.ambassador.RunCmd(cmd)
	if err != nil {
		log.WithFields(log.Fields{
			"image_ref_repository": imageRef.Repository,
			"image_ref_tag":        imageRef.Tag,
			"image_ref_digest":     imageRef.Digest,
			"exit_code":            exitCode,
			"std_out":              string(stdout),
		}).Error("Error while running scannercli command")
		return report, fmt.Errorf("running command: %v: %v", err, string(stdout))
	}

	log.WithFields(log.Fields{
		"image_ref_repository": imageRef.Repository,
		"image_ref_tag":        imageRef.Tag,
		"image_ref_digest":     imageRef.Digest,
		"exit_code":            exitCode,
		"std_out":              string(stdout),
	}).Trace("Running scannercli command finished")

	err = json.NewDecoder(reportFile).Decode(&report)
	if err != nil {
		return report, fmt.Errorf("decoding scan report from file: %w", err)
	}
	return
}

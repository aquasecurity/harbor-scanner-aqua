package aqua

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

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

// Command represents the CLI interface for the Aqua Enterprise scanner,
// i.e. scannercli executable.
type Command interface {
	Scan(imageRef ImageRef) (ScanReport, error)
}

// NewCommand constructs Aqua Enterprise scanner command with the given configuration.
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
	if c.cfg.ReportDelete {
		defer func() {
			log.WithField("path", reportFile.Name()).Debug("Removing tmp scan report file")
			err := c.ambassador.Remove(reportFile.Name())
			if err != nil {
				log.WithError(err).Warn("Error while removing tmp scan report file")
			}
		}()
	} else {
		log.WithField("path", reportFile.Name()).Warn("tmp scan report file was stored")
	}

	image := imageRef.WithDigest()
	if c.cfg.UseImageTag && imageRef.WithTag() != "" {
		repoAndTag := strings.Split(imageRef.WithTag(), ":")
		if len(repoAndTag) == 2 && len(strings.TrimSpace(repoAndTag[1])) != 0 {
			log.WithField("input image name", c.cfg.UseImageTag).Infof("got proper image name:tag")
			image = imageRef.WithTag()
		} else {
			log.WithField("input image name", c.cfg.UseImageTag).WithField("input digest", imageRef.WithDigest()).
				Infof("failed with tag..proceeding with digest")
		}
	}
	args := []string{
		"scan",
		"--checkonly",
		"--dockerless",
		fmt.Sprintf("--host=%s", c.cfg.Host),
		fmt.Sprintf("--registry=%s", c.cfg.Registry),
		fmt.Sprintf("--no-verify=%t", c.cfg.ScannerCLINoVerify),
		fmt.Sprintf("--direct-cc=%t", c.cfg.ScannerCLIDirectCC),
		fmt.Sprintf("--show-negligible=%t", c.cfg.ScannerCLIShowNegligible),
		fmt.Sprintf("--jsonfile=%s", reportFile.Name()),
	}

	switch c.cfg.ScannerCLIRegisterImages {
	case etc.Never:
		// Do nothing
	case etc.Always:
		args = append(args, "--register")
	case etc.Compliant:
		args = append(args, "--register-compliant")
	}

	log.WithFields(log.Fields{"exec": executable, "args": args}).Debug("Running scannercli")

	if c.cfg.ScannerCLIOverrideRegistryCredentials {
		args = append(args, fmt.Sprintf("--robot-username=%s", imageRef.Auth.Username),
			fmt.Sprintf("--robot-password=%s", imageRef.Auth.Password))
	}

	if c.cfg.Token != "" {
		args = append(args, fmt.Sprintf("--token=%s", c.cfg.Token),image)
	} else {
		args = append(args, fmt.Sprintf("--password=%s", c.cfg.Password),
			fmt.Sprintf("--user=%s", c.cfg.Username),image)
	}

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

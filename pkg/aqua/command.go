package aqua

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"io/ioutil"
	"os"
	"os/exec"
)

const assurancePolicyCheckFailed = 4

type ImageRef struct {
	Repository string
	Tag        string
	Digest     string
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
	Exec(imageRef ImageRef) (ScanReport, error)
}

// NewCommands constructs Aqua CSP scanner command with the given configuration.
func NewCommand(cfg etc.AquaCSP) Command {
	return &command{
		cfg: cfg,
	}
}

type command struct {
	cfg etc.AquaCSP
}

func (c *command) Exec(imageRef ImageRef) (report ScanReport, err error) {
	executable, err := exec.LookPath("scannercli")
	if err != nil {
		return report, xerrors.Errorf("searching for scannercli executable: %w", err)
	}
	reportFile, err := ioutil.TempFile(c.cfg.ReportsDir, "scan_report_*.json")
	if err != nil {
		return report, xerrors.Errorf("creating tmp file for scan report: %w", err)
	}
	log.WithField("path", reportFile.Name()).Debug("Saving scan report to tmp file")
	defer func() {
		log.WithField("path", reportFile.Name()).Debug("Removing scan report tmp file")
		err := os.Remove(reportFile.Name())
		if err != nil {
			log.WithError(err).Warn("Error while removing scan report file")
		}
	}()

	image := imageRef.WithDigest()
	if c.cfg.UseImageTag {
		image = imageRef.WithTag()
	}

	args := []string{
		"scan",
		"--user", c.cfg.User,
		"--password", c.cfg.Password,
		"--host", c.cfg.Host,
		"--registry", c.cfg.Registry,
		"--dockerless",
		"--jsonfile", reportFile.Name(),
		image,
	}

	log.WithFields(log.Fields{"exec": executable, "args": args}).Trace("Running scannercli")

	cmd := exec.Command(executable, args...)

	stderrBuffer := bytes.Buffer{}

	cmd.Stderr = &stderrBuffer

	stdout, err := cmd.Output()
	if err != nil && cmd.ProcessState.ExitCode() != assurancePolicyCheckFailed {
		log.WithFields(log.Fields{
			"image_ref": imageRef,
			"exit_code": cmd.ProcessState.ExitCode(),
			"std_err":   stderrBuffer.String(),
			"std_out":   string(stdout),
		}).Error("Error while running scannercli command")
		return report, xerrors.Errorf("running command: %v: %v", err, stderrBuffer.String())
	}

	log.WithFields(log.Fields{
		"image_ref": imageRef,
		"exit_code": cmd.ProcessState.ExitCode(),
		"std_err":   stderrBuffer.String(),
		"std_out":   string(stdout),
	}).Trace("Running scannercli command finished")

	if cmd.ProcessState.ExitCode() == assurancePolicyCheckFailed {
		log.WithFields(log.Fields{
			"image_ref": imageRef,
		}).Warn("Some assurance policy checks configured in Aqua management console failed. Navigate to Aqua management console for details.")
	}

	err = json.NewDecoder(reportFile).Decode(&report)
	if err != nil {
		return report, xerrors.Errorf("decoding scan report from file %v", err)
	}
	return
}

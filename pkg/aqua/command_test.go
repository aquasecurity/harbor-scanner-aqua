package aqua

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/ext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	NoError error = nil
)

func TestCommand_Scan(t *testing.T) {

	config := etc.AquaCSP{
		ReportsDir:                            "/var/lib/reports",
		Username:                              "scanner",
		Password:                              "ch@ng3me!",
		Host:                                  "https://aqua.domain:8080",
		Registry:                              "Harbor",
		UseImageTag:                           true,
		ScannerCLINoVerify:                    true,
		ScannerCLIShowNegligible:              true,
		ScannerCLIOverrideRegistryCredentials: true,
		ScannerCLIDirectCC:                    true,
		ScannerCLIRegisterImages:              etc.Compliant,
		ReportDelete:                          true,
	}

	imageRef := ImageRef{
		Repository: "library/alpine",
		Tag:        "3.10.2",
		Auth: RegistryAuth{
			Username: "robotName",
			Password: "robotPassword",
		},
	}

	t.Run("Should return error when scannercli lookup returns error", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("LookPath", "scannercli").
			Return("/usr/local/bin/scannercli", errors.New("not found"))

		_, err := NewCommand(config, ambassador).Scan(ImageRef{})
		assert.EqualError(t, err, "searching for scannercli executable: not found")
		ambassador.AssertExpectations(t)
	})

	t.Run("Should return error when creating tmp file returns error", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("LookPath", "scannercli").
			Return("/usr/local/bin/scannercli", NoError)
		ambassador.On("TempFile", config.ReportsDir, "aqua_scan_report_*.json").
			Return(nil, errors.New("no more space"))

		_, err := NewCommand(config, ambassador).Scan(ImageRef{})
		assert.EqualError(t, err, "creating tmp scan report file: no more space")
		ambassador.AssertExpectations(t)
	})

	t.Run("Should return error when running scannercli command returns error", func(t *testing.T) {
		ambassador := ext.NewMockAmbassador()
		ambassador.On("LookPath", "scannercli").
			Return("/usr/local/bin/scannercli", NoError)
		ambassador.On("TempFile", config.ReportsDir, "aqua_scan_report_*.json").
			Return(ext.NewFakeFile("/var/lib/scanner/reports/aqua_scan_report_1234567890.json", strings.NewReader("{}")), NoError)
		ambassador.On("Remove", "/var/lib/scanner/reports/aqua_scan_report_1234567890.json").
			Return(NoError)
		ambassador.On("RunCmd", &exec.Cmd{
			Path: "/usr/local/bin/scannercli",
			Args: []string{
				"/usr/local/bin/scannercli", "scan",
				"--checkonly",
				"--dockerless",
				"--host=https://aqua.domain:8080",
				"--registry=Harbor",
				"--no-verify=true",
				"--direct-cc=true",
				"--show-negligible=true",
				"--jsonfile=/var/lib/scanner/reports/aqua_scan_report_1234567890.json",
				"--register-compliant",
				"--robot-username=robotName",
				"--robot-password=robotPassword",
				"--user=scanner",
				"--password=ch@ng3me!",
				"library/alpine:3.10.2",
			},
		}).Return([]byte("killed"), 137, errors.New("boom"))

		_, err := NewCommand(config, ambassador).Scan(imageRef)
		assert.EqualError(t, err, "running command: boom: killed")
		ambassador.AssertExpectations(t)
	})

	/*
		This test checks the tmp report isn't removed.
		There is no mock for `Remove` method, so there will be panic for removing the tmp report.
	*/
	t.Run("Should store the tmp report file", func(t *testing.T) {
		aquaReportJSON, err := os.Open("test_fixtures/aqua_report_photon_3.0.json")
		require.NoError(t, err)
		defer func() {
			_ = aquaReportJSON.Close()
		}()
		config.ReportDelete = false
		defer func() {
			config.ReportDelete = true
		}()
		ambassador := ext.NewMockAmbassador()
		ambassador.On("LookPath", "scannercli").
			Return("/usr/local/bin/scannercli", NoError)
		ambassador.On("TempFile", config.ReportsDir, "aqua_scan_report_*.json").
			Return(ext.NewFakeFile("/var/lib/scanner/reports/aqua_scan_report_1234567890.json", aquaReportJSON), NoError)
		//		ambassador.On("Remove", "/var/lib/scanner/reports/aqua_scan_report_1234567890.json").
		//			Return(NoError)
		ambassador.On("RunCmd", &exec.Cmd{
			Path: "/usr/local/bin/scannercli",
			Args: []string{
				"/usr/local/bin/scannercli", "scan",
				"--checkonly",
				"--dockerless",
				"--host=https://aqua.domain:8080",
				"--registry=Harbor",
				"--no-verify=true",
				"--direct-cc=true",
				"--show-negligible=true",
				"--jsonfile=/var/lib/scanner/reports/aqua_scan_report_1234567890.json",
				"--register-compliant",
				"--robot-username=robotName",
				"--robot-password=robotPassword",
				"--user=scanner",
				"--password=ch@ng3me!",
				"library/alpine:3.10.2",
			},
		}).Return([]byte{}, 0, NoError)
		aquaReport, err := NewCommand(config, ambassador).Scan(imageRef)
		require.NoError(t, err)
		assert.Equal(t, ScanReport{
			Image:          "library/photon@sha256:ba6a5e0592483f28827545ce100f711aa602adf100e5884840c56c5b9b059acc",
			Registry:       "Harbor",
			Digest:         "",
			PullName:       "core.harbor.domain/library/photon:sha256:ba6a5e0592483f28827545ce100f711aa602adf100e5884840c56c5b9b059acc",
			OS:             "photon",
			Version:        "3.0",
			PartialResults: true,
			ChangedResults: false,
			InitiatingUser: "administrator",
			Resources: []ResourceScan{
				{
					Resource: Resource{
						Format:  "",
						Type:    Package,
						Path:    "/usr/bin/bash",
						Name:    "bash",
						Version: "4.4",
						CPE:     "cpe:/a:gnu:bash:4.4",
					},
					Scanned: true,
					Vulnerabilities: []Vulnerability{
						{
							Name:              "CVE-2017-5932",
							Description:       "The path autocompletion feature in Bash 4.4 allows local users to gain privileges via a crafted filename starting with a \" (double quote) character and a command substitution metacharacter.",
							NVDURL:            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5932",
							VendorURL:         "",
							FixVersion:        "",
							AquaScore:         7.8,
							AquaSeverity:      "high",
							AquaVectors:       "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							AquaScoringSystem: "CVSS V3",
						},
						{
							Name:              "CVE-2019-18276",
							Description:       "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
							NVDURL:            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-18276",
							VendorURL:         "",
							FixVersion:        "",
							AquaScore:         7.8,
							AquaSeverity:      "high",
							AquaVectors:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							AquaScoringSystem: "CVSS V3",
						},
					},
				},
				{
					Resource: Resource{
						Format:  "",
						Type:    Package,
						Path:    "/usr/bin/gencat",
						Name:    "glibc",
						Version: "2.28",
						CPE:     "cpe:/a:gnu:glibc:2.28",
					},
					Scanned: true,
					Vulnerabilities: []Vulnerability{
						{
							Name:              "CVE-2019-9169",
							Description:       "In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-based buffer over-read via an attempted case-insensitive regular-expression match.",
							NVDURL:            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-9169",
							VendorURL:         "",
							FixVersion:        "",
							AquaScore:         9.8,
							AquaSeverity:      "critical",
							AquaVectors:       "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							AquaScoringSystem: "CVSS V3",
						},
					},
				},
			},
			Summary: Summary{
				Total:      12,
				Critical:   2,
				High:       6,
				Medium:     3,
				Low:        1,
				Negligible: 0,
				Sensitive:  0,
				Malware:    0,
			},
			ScanOptions: ScanOptions{
				ScanExecutables:          true,
				ShowWillNotFix:           true,
				StrictScan:               true,
				ScanMalware:              false,
				ScanFiles:                true,
				ManualPullFallback:       true,
				SaveAdHockScans:          true,
				Dockerless:               true,
				EnableFastScanning:       true,
				SuggestOSUpgrade:         true,
				IncludeSiblingAdvisories: true,
				UseCVSS3:                 true,
			},
		}, aquaReport)

		ambassador.AssertExpectations(t)
	})

	t.Run("Should return scan report", func(t *testing.T) {
		aquaReportJSON, err := os.Open("test_fixtures/aqua_report_photon_3.0.json")
		require.NoError(t, err)
		defer func() {
			_ = aquaReportJSON.Close()
		}()
		ambassador := ext.NewMockAmbassador()
		ambassador.On("LookPath", "scannercli").
			Return("/usr/local/bin/scannercli", NoError)
		ambassador.On("TempFile", config.ReportsDir, "aqua_scan_report_*.json").
			Return(ext.NewFakeFile("/var/lib/scanner/reports/aqua_scan_report_1234567890.json", aquaReportJSON), NoError)
		ambassador.On("Remove", "/var/lib/scanner/reports/aqua_scan_report_1234567890.json").
			Return(NoError)
		ambassador.On("RunCmd", &exec.Cmd{
			Path: "/usr/local/bin/scannercli",
			Args: []string{
				"/usr/local/bin/scannercli", "scan",
				"--checkonly",
				"--dockerless",
				"--host=https://aqua.domain:8080",
				"--registry=Harbor",
				"--no-verify=true",
				"--direct-cc=true",
				"--show-negligible=true",
				"--jsonfile=/var/lib/scanner/reports/aqua_scan_report_1234567890.json",
				"--register-compliant",
				"--robot-username=robotName",
				"--robot-password=robotPassword",
				"--user=scanner",
				"--password=ch@ng3me!",
				"library/alpine:3.10.2",
			},
		}).Return([]byte{}, 0, NoError)

		aquaReport, err := NewCommand(config, ambassador).Scan(imageRef)
		require.NoError(t, err)
		assert.Equal(t, ScanReport{
			Image:          "library/photon@sha256:ba6a5e0592483f28827545ce100f711aa602adf100e5884840c56c5b9b059acc",
			Registry:       "Harbor",
			Digest:         "",
			PullName:       "core.harbor.domain/library/photon:sha256:ba6a5e0592483f28827545ce100f711aa602adf100e5884840c56c5b9b059acc",
			OS:             "photon",
			Version:        "3.0",
			PartialResults: true,
			ChangedResults: false,
			InitiatingUser: "administrator",
			Resources: []ResourceScan{
				{
					Resource: Resource{
						Format:  "",
						Type:    Package,
						Path:    "/usr/bin/bash",
						Name:    "bash",
						Version: "4.4",
						CPE:     "cpe:/a:gnu:bash:4.4",
					},
					Scanned: true,
					Vulnerabilities: []Vulnerability{
						{
							Name:              "CVE-2017-5932",
							Description:       "The path autocompletion feature in Bash 4.4 allows local users to gain privileges via a crafted filename starting with a \" (double quote) character and a command substitution metacharacter.",
							NVDURL:            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-5932",
							VendorURL:         "",
							FixVersion:        "",
							AquaScore:         7.8,
							AquaSeverity:      "high",
							AquaVectors:       "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							AquaScoringSystem: "CVSS V3",
						},
						{
							Name:              "CVE-2019-18276",
							Description:       "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
							NVDURL:            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-18276",
							VendorURL:         "",
							FixVersion:        "",
							AquaScore:         7.8,
							AquaSeverity:      "high",
							AquaVectors:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
							AquaScoringSystem: "CVSS V3",
						},
					},
				},
				{
					Resource: Resource{
						Format:  "",
						Type:    Package,
						Path:    "/usr/bin/gencat",
						Name:    "glibc",
						Version: "2.28",
						CPE:     "cpe:/a:gnu:glibc:2.28",
					},
					Scanned: true,
					Vulnerabilities: []Vulnerability{
						{
							Name:              "CVE-2019-9169",
							Description:       "In the GNU C Library (aka glibc or libc6) through 2.29, proceed_next_node in posix/regexec.c has a heap-based buffer over-read via an attempted case-insensitive regular-expression match.",
							NVDURL:            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2019-9169",
							VendorURL:         "",
							FixVersion:        "",
							AquaScore:         9.8,
							AquaSeverity:      "critical",
							AquaVectors:       "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							AquaScoringSystem: "CVSS V3",
						},
					},
				},
			},
			Summary: Summary{
				Total:      12,
				Critical:   2,
				High:       6,
				Medium:     3,
				Low:        1,
				Negligible: 0,
				Sensitive:  0,
				Malware:    0,
			},
			ScanOptions: ScanOptions{
				ScanExecutables:          true,
				ShowWillNotFix:           true,
				StrictScan:               true,
				ScanMalware:              false,
				ScanFiles:                true,
				ManualPullFallback:       true,
				SaveAdHockScans:          true,
				Dockerless:               true,
				EnableFastScanning:       true,
				SuggestOSUpgrade:         true,
				IncludeSiblingAdvisories: true,
				UseCVSS3:                 true,
			},
		}, aquaReport)

		ambassador.AssertExpectations(t)
	})

}

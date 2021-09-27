package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTransformer_Transform(t *testing.T) {
	now := time.Now()

	artifact := harbor.Artifact{
		Repository: "library/golang",
		Tag:        "1.12.4",
	}

	aquaReport := aqua.ScanReport{
		Resources: []aqua.ResourceScan{
			{
				Resource: aqua.Resource{
					Type:    aqua.Package,
					Name:    "openssl",
					Version: "2.8.3",
				},
				Vulnerabilities: []aqua.Vulnerability{
					{
						Name:         "CVE-0001-0020",
						AquaSeverity: "high",
						NVDURL:       "http://nvd?id=CVE-0001-0020",
					},
					{
						Name:         "CVE-3045-2011",
						AquaSeverity: "low",
					},
				},
			},
			{
				Resource: aqua.Resource{
					Type: aqua.Library,
					Path: "/app/main.rb",
				},
				Vulnerabilities: []aqua.Vulnerability{
					{
						Name:         "CVE-9900-1100",
						AquaSeverity: "critical",
					},
				},
			},
		},
	}

	harborReport := NewTransformer(ext.NewFixedClock(now)).Transform(artifact, aquaReport)
	assert.Equal(t, harbor.ScanReport{
		GeneratedAt: now,
		Artifact: harbor.Artifact{
			Repository: "library/golang",
			Tag:        "1.12.4",
		},
		Scanner: harbor.Scanner{
			Name:    "Aqua Enterprise",
			Vendor:  "Aqua Security",
			Version: "Unknown",
		},
		Severity: harbor.SevCritical,
		Vulnerabilities: []harbor.VulnerabilityItem{
			{
				ID:       "CVE-0001-0020",
				Pkg:      "openssl",
				Version:  "2.8.3",
				Severity: harbor.SevHigh,
				Links: []string{
					"http://nvd?id=CVE-0001-0020",
				},
			},
			{
				ID:       "CVE-3045-2011",
				Pkg:      "openssl",
				Version:  "2.8.3",
				Severity: harbor.SevLow,
				Links:    ([]string)(nil),
			},
			{
				ID:       "CVE-9900-1100",
				Pkg:      "/app/main.rb",
				Version:  "",
				Severity: harbor.SevCritical,
				Links:    ([]string)(nil),
			},
		},
	}, harborReport)
}

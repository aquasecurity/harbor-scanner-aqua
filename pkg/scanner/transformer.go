package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/clock"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	log "github.com/sirupsen/logrus"
)

type Transformer interface {
	Transform(artifact harbor.Artifact, source aqua.ScanReport) harbor.ScanReport
}

func NewTransformer(clock clock.Clock) Transformer {
	return &transformer{
		clock: clock,
	}
}

type transformer struct {
	clock clock.Clock
}

func (t *transformer) Transform(artifact harbor.Artifact, source aqua.ScanReport) harbor.ScanReport {
	var items []harbor.VulnerabilityItem

	for _, resourceScan := range source.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			var pkg string
			switch resourceScan.Resource.Type {
			case aqua.Library:
				pkg = resourceScan.Resource.Path
			case aqua.Package:
				pkg = resourceScan.Resource.Name
			default:
				continue
			}
			items = append(items, harbor.VulnerabilityItem{
				ID:          vln.Name,
				Pkg:         pkg,
				Version:     resourceScan.Resource.Version,
				FixVersion:  vln.FixVersion,
				Severity:    t.getHarborSeverity(vln),
				Description: vln.Description,
				Links:       t.toLinks(vln),
			})
		}
	}

	return harbor.ScanReport{
		GeneratedAt:     t.clock.Now(),
		Scanner:         etc.GetScannerMetadata(),
		Artifact:        artifact,
		Severity:        t.getHighestSeverity(items),
		Vulnerabilities: items,
	}
}

func (t *transformer) getHarborSeverity(v aqua.Vulnerability) harbor.Severity {
	var severity harbor.Severity
	switch v.AquaSeverity {
	case "critical":
		severity = harbor.SevCritical
	case "high":
		severity = harbor.SevHigh
	case "medium":
		severity = harbor.SevMedium
	case "low":
		severity = harbor.SevLow
	default:
		log.WithField("severity", v.AquaSeverity).Warn("Unknown Aqua severity")
		severity = harbor.SevUnknown
	}
	log.WithFields(log.Fields{"vulnerability": v, "severity": severity}).Trace("Mapping severity")
	return severity
}

func (t *transformer) toLinks(v aqua.Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	return links
}

func (t *transformer) getHighestSeverity(items []harbor.VulnerabilityItem) (highest harbor.Severity) {
	highest = harbor.SevUnknown

	for _, v := range items {
		if v.Severity > highest {
			highest = v.Severity
		}
	}

	return
}

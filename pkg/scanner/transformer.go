package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	log "github.com/sirupsen/logrus"
)

type Transformer interface {
	Transform(artifact harbor.Artifact, source aqua.ScanReport) harbor.ScanReport
}

func NewTransformer(clock ext.Clock) Transformer {
	return &transformer{
		clock: clock,
	}
}

type transformer struct {
	clock ext.Clock
}

func (t *transformer) Transform(artifact harbor.Artifact, source aqua.ScanReport) harbor.ScanReport {
	log.WithFields(log.Fields{
		"digest":          source.Digest,
		"image":           source.Image,
		"summary":         source.Summary,
		"scan_options":    source.ScanOptions,
		"changed_results": source.ChangedResults,
		"partial_results": source.PartialResults,
	}).Debug("Transforming scan report")
	var items []harbor.VulnerabilityItem

	for _, resourceScan := range source.Resources {
		var pkg string
		switch resourceScan.Resource.Type {
		case aqua.Library:
			pkg = resourceScan.Resource.Path
		case aqua.Package:
			pkg = resourceScan.Resource.Name
		default:
			pkg = resourceScan.Resource.Name
		}

		for _, vln := range resourceScan.Vulnerabilities {
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
	case "negligible":
		severity = harbor.SevNegligible
	default:
		log.WithField("severity", v.AquaSeverity).Warn("Unknown Aqua severity")
		severity = harbor.SevUnknown
	}
	return severity
}

func (t *transformer) toLinks(v aqua.Vulnerability) []string {
	var links []string
	if v.NVDURL != "" {
		links = append(links, v.NVDURL)
	}
	if v.VendorURL != "" {
		links = append(links, v.VendorURL)
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

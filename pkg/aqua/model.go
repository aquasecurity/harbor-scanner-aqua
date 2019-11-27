package aqua

type ResourceType int

const (
	_ ResourceType = iota
	Library
	Package
)

type ScanReport struct {
	Image     string         `json:"image"`
	Registry  string         `json:"registry"`
	Digest    string         `json:"digest"`
	OS        string         `json:"os"`
	Version   string         `json:"version"`
	Resources []ResourceScan `json:"resources"`
	Summary   Summary        `json:"vulnerability_summary"`
}

type ResourceScan struct {
	Resource        Resource        `json:"resource"`
	Scanned         bool            `json:"scanned"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Resource struct {
	Type    ResourceType `json:"type"`
	Path    string       `json:"path"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
}

type Vulnerability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	FixVersion  string `json:"fix_version"`

	VendorURL        string `json:"vendor_url"`
	VendorSeverity   string `json:"vendor_severity"`
	VendorSeverityV3 string `json:"vendor_severity_v3"`

	NVDURL        string  `json:"nvd_url"`
	NVDSeverity   string  `json:"nvd_severity"`
	NVDScore      float32 `json:"nvd_score"`
	NVDSeverityV3 string  `json:"nvd_severity_v3"`
	NVDScoreV3    float32 `json:"nvd_score_v3"`

	AquaSeverity      string  `json:"aqua_severity"`
	AquaScore         float32 `json:"aqua_score"`
	AquaScoringSystem string  `json:"aqua_scoring_system"`
}

type Summary struct {
	Total      int `json:"total"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Sensitive  int `json:"sensitive"`
	Malware    int `json:"malware"`
}

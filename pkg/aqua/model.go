package aqua

type ResourceType int

const (
	_ ResourceType = iota
	Library
	Package
)

type ScanReport struct {
	Image          string         `json:"image"`
	Registry       string         `json:"registry"`
	Digest         string         `json:"digest"`
	PullName       string         `json:"pull_name"`
	OS             string         `json:"os"`
	Version        string         `json:"version"`
	PartialResults bool           `json:"partial_results"`
	ChangedResults bool           `json:"changed_results"`
	InitiatingUser string         `json:"initiating_user"`
	Resources      []ResourceScan `json:"resources"`
	Summary        Summary        `json:"vulnerability_summary"`
	ScanOptions    ScanOptions    `json:"scan_options"`
}

type ResourceScan struct {
	Resource        Resource        `json:"resource"`
	Scanned         bool            `json:"scanned"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Resource struct {
	Format  string       `json:"format"`
	Type    ResourceType `json:"type"`
	Path    string       `json:"path"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	CPE     string       `json:"cpe"` // CPE Common Platform Enumerations
}

type Vulnerability struct {
	Name              string  `json:"name"`
	Description       string  `json:"description"`
	NVDURL            string  `json:"nvd_url"`
	VendorURL         string  `json:"vendor_url"`
	FixVersion        string  `json:"fix_version"`
	AquaScore         float32 `json:"aqua_score"`
	AquaSeverity      string  `json:"aqua_severity"`
	AquaVectors       string  `json:"aqua_vectors"`
	AquaScoringSystem string  `json:"aqua_scoring_system"`
}

type Summary struct {
	Total      int `json:"total"`
	Critical   int `json:"critical"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Negligible int `json:"negligible"`
	Sensitive  int `json:"sensitive"`
	Malware    int `json:"malware"`
}

type ScanOptions struct {
	ScanExecutables          bool `json:"scan_executables"`
	ShowWillNotFix           bool `json:"show_will_not_fix"`
	StrictScan               bool `json:"strict_scan"`
	ScanMalware              bool `json:"scan_malware"`
	ScanFiles                bool `json:"scan_files"`
	ManualPullFallback       bool `json:"manual_pull_fallback"`
	SaveAdHockScans          bool `json:"save_adhoc_scans"`
	Dockerless               bool `json:"dockerless"`
	EnableFastScanning       bool `json:"enable_fast_scanning"`
	SuggestOSUpgrade         bool `json:"suggest_os_upgrade"`
	IncludeSiblingAdvisories bool `json:"include_sibling_advisories"`
	UseCVSS3                 bool `json:"use_cvss3"`
}

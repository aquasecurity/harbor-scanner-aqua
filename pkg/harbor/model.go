package harbor

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`
}

type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

package harbor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevUnknown
	SevNegligible
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

var severityToString = map[Severity]string{
	SevUnknown:    "Unknown",
	SevNegligible: "Negligible",
	SevLow:        "Low",
	SevMedium:     "Medium",
	SevHigh:       "High",
	SevCritical:   "Critical",
}

var stringToSeverity = map[string]Severity{
	"Unknown":    SevUnknown,
	"Negligible": SevNegligible,
	"Low":        SevLow,
	"Medium":     SevMedium,
	"High":       SevHigh,
	"Critical":   SevCritical,
}

// MarshalJSON marshals the Severity enum value as a quoted JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(severityToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals quoted JSON string to the Severity enum value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err != nil {
		return err
	}
	*s = stringToSeverity[value]
	return nil
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

func (r Registry) GetBasicCredentials() (username, password string, err error) {
	tokens := strings.Split(r.Authorization, " ")
	if len(tokens) != 2 {
		err = fmt.Errorf("parsing authorization: expected <type> <credentials> got [%s]", r.Authorization)
		return
	}
	switch tokens[0] {
	case "Basic":
		return r.decodeBasicAuthentication(tokens[1])
	}
	err = fmt.Errorf("unsupported authorization type: %s", tokens[0])
	return
}

func (r Registry) decodeBasicAuthentication(value string) (username, password string, err error) {
	creds, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return
	}
	tokens := strings.Split(string(creds), ":")
	if len(tokens) != 2 {
		err = errors.New("username and password not split by single colon")
		return
	}

	username = tokens[0]
	password = tokens[1]

	return
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag"`
	MimeType   string `json:"mime_type,omitempty"`
}

type ScanRequest struct {
	Registry Registry `json:"registry"`
	Artifact Artifact `json:"artifact"`
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Artifact        Artifact            `json:"artifact"`
	Scanner         Scanner             `json:"scanner"`
	Severity        Severity            `json:"severity"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID          string   `json:"id"`
	Pkg         string   `json:"package"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version,omitempty"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
}

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

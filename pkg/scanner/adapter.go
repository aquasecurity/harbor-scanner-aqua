package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
)

type Adapter interface {
	Scan(req harbor.ScanRequest) (harbor.ScanReport, error)
}

type adapter struct {
	command     aqua.Command
	transformer Transformer
}

func NewAdapter(command aqua.Command, transformer Transformer) Adapter {
	return &adapter{
		command:     command,
		transformer: transformer,
	}
}

func (s *adapter) Scan(req harbor.ScanRequest) (harbor.ScanReport, error) {
	aquaScanReport, err := s.command.Exec(aqua.ImageRef{
		Repository: req.Artifact.Repository,
		Tag:        req.Artifact.Tag,
		Digest:     req.Artifact.Digest,
	})
	if err != nil {
		return harbor.ScanReport{}, err
	}
	harborScanReport := s.transformer.Transform(req.Artifact, aquaScanReport)
	return harborScanReport, nil
}

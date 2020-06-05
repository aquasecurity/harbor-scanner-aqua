package scanner

import (
	"fmt"

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

func (s *adapter) Scan(req harbor.ScanRequest) (harborReport harbor.ScanReport, err error) {
	username, password, err := req.Registry.GetBasicCredentials()
	if err != nil {
		err = fmt.Errorf("getting basic credentials from scan request: %w", err)
		return
	}

	aquaReport, err := s.command.Scan(aqua.ImageRef{
		Repository: req.Artifact.Repository,
		Tag:        req.Artifact.Tag,
		Digest:     req.Artifact.Digest,
		Auth: aqua.RegistryAuth{
			Username: username,
			Password: password,
		},
	})
	if err != nil {
		return
	}
	harborReport = s.transformer.Transform(req.Artifact, aquaReport)
	return
}

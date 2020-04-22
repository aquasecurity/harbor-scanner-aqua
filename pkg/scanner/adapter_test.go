package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAdapter_Scan(t *testing.T) {
	command := &aqua.MockCommand{}
	transformer := &MockTransformer{}

	artifact := harbor.Artifact{
		Repository: "library/golang",
		Tag:        "1.12.4",
	}
	scanRequest := harbor.ScanRequest{
		Artifact: artifact,
	}

	aquaReport := aqua.ScanReport{}
	harborReport := harbor.ScanReport{}

	command.On("Scan", aqua.ImageRef{Repository: "library/golang", Tag: "1.12.4"}).Return(aquaReport, nil)
	transformer.On("Transform", artifact, aquaReport).Return(harborReport)

	adapter := NewAdapter(command, transformer)
	r, err := adapter.Scan(scanRequest)
	require.NoError(t, err)
	require.Equal(t, harborReport, r)

	command.AssertExpectations(t)
	transformer.AssertExpectations(t)
}

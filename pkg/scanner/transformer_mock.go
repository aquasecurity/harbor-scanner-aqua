package scanner

import (
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/aqua"
	"github.com/aquasecurity/harbor-scanner-aqua/pkg/harbor"
	"github.com/stretchr/testify/mock"
)

type MockTransformer struct {
	mock.Mock
}

func (t *MockTransformer) Transform(artifact harbor.Artifact, source aqua.ScanReport) harbor.ScanReport {
	args := t.Called(artifact, source)
	return args.Get(0).(harbor.ScanReport)
}

package ext

import (
	"github.com/stretchr/testify/mock"
	"io"
	"os/exec"
)

type FakeFile struct {
	name   string
	reader io.Reader
}

// NewFakeFile constructs a new FakeFile with the given name and content.
func NewFakeFile(name string, content io.Reader) *FakeFile {
	return &FakeFile{
		name:   name,
		reader: content,
	}
}

func (ff *FakeFile) Name() string {
	return ff.name
}

func (ff *FakeFile) Read(p []byte) (int, error) {
	return ff.reader.Read(p)
}

type MockAmbassador struct {
	mock.Mock
}

func NewMockAmbassador() *MockAmbassador {
	return &MockAmbassador{}
}

func (m *MockAmbassador) Environ() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockAmbassador) LookPath(file string) (string, error) {
	args := m.Called(file)
	return args.String(0), args.Error(1)
}

func (m *MockAmbassador) RunCmd(cmd *exec.Cmd) ([]byte, int, error) {
	args := m.Called(cmd)
	return args.Get(0).([]byte), args.Int(1), args.Error(2)
}

func (m *MockAmbassador) TempFile(dir, pattern string) (file File, err error) {
	args := m.Called(dir, pattern)
	if arg := args.Get(0); arg != nil {
		file = arg.(File)
	}
	err = args.Error(1)
	return
}

func (m *MockAmbassador) Remove(name string) error {
	args := m.Called(name)
	return args.Error(0)
}

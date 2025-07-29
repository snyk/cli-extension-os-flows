package outputworkflow

import (
	"io"
	"io/fs"
	"reflect"

	"github.com/golang/mock/gomock"
)

// MockOutputDestination is a mock of OutputDestination interface.
type MockOutputDestination struct {
	ctrl     *gomock.Controller
	recorder *MockOutputDestinationMockRecorder
}

// MockOutputDestinationMockRecorder is the mock recorder for MockOutputDestination.
type MockOutputDestinationMockRecorder struct {
	mock *MockOutputDestination
}

// NewMockOutputDestination creates a new mock instance.
func NewMockOutputDestination(ctrl *gomock.Controller) *MockOutputDestination {
	mock := &MockOutputDestination{ctrl: ctrl}
	mock.recorder = &MockOutputDestinationMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockOutputDestination) EXPECT() *MockOutputDestinationMockRecorder {
	return m.recorder
}

// GetWriter mocks base method.
//
//nolint:ireturn // expected to return an interface for flexibility
func (m *MockOutputDestination) GetWriter() io.Writer {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetWriter")
	ret0, _ := ret[0].(io.Writer) //nolint:errcheck // Mock code
	return ret0
}

// GetWriter indicates an expected call of GetWriter.
func (mr *MockOutputDestinationMockRecorder) GetWriter() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetWriter", reflect.TypeOf((*MockOutputDestination)(nil).GetWriter))
}

// Println mocks base method.
func (m *MockOutputDestination) Println(a ...interface{}) (int, error) {
	m.ctrl.T.Helper()
	var varargs []interface{}
	varargs = append(varargs, a...)
	ret := m.ctrl.Call(m, "Println", varargs...)
	ret0, _ := ret[0].(int)   //nolint:errcheck // Mock code
	ret1, _ := ret[1].(error) //nolint:errcheck // Mock code
	return ret0, ret1
}

// Println indicates an expected call of Println.
func (mr *MockOutputDestinationMockRecorder) Println(a ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Println", reflect.TypeOf((*MockOutputDestination)(nil).Println), a...)
}

// Remove mocks base method.
func (m *MockOutputDestination) Remove(name string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", name)
	ret0, _ := ret[0].(error) //nolint:errcheck // Mock code
	return ret0
}

// Remove indicates an expected call of Remove.
func (mr *MockOutputDestinationMockRecorder) Remove(name interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockOutputDestination)(nil).Remove), name)
}

// WriteFile mocks base method.
func (m *MockOutputDestination) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteFile", filename, data, perm)
	ret0, _ := ret[0].(error) //nolint:errcheck // Mock code
	return ret0
}

// WriteFile indicates an expected call of WriteFile.
func (mr *MockOutputDestinationMockRecorder) WriteFile(filename, data, perm interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteFile", reflect.TypeOf((*MockOutputDestination)(nil).WriteFile), filename, data, perm)
}

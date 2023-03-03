// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/tzrd/saml/pkg/provider/models (interfaces: AuthRequestInt)

// Package mock is a generated GoMock package.
package mock

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockAuthRequestInt is a mock of AuthRequestInt interface
type MockAuthRequestInt struct {
	ctrl     *gomock.Controller
	recorder *MockAuthRequestIntMockRecorder
}

// MockAuthRequestIntMockRecorder is the mock recorder for MockAuthRequestInt
type MockAuthRequestIntMockRecorder struct {
	mock *MockAuthRequestInt
}

// NewMockAuthRequestInt creates a new mock instance
func NewMockAuthRequestInt(ctrl *gomock.Controller) *MockAuthRequestInt {
	mock := &MockAuthRequestInt{ctrl: ctrl}
	mock.recorder = &MockAuthRequestIntMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockAuthRequestInt) EXPECT() *MockAuthRequestIntMockRecorder {
	return m.recorder
}

// Done mocks base method
func (m *MockAuthRequestInt) Done() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Done")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Done indicates an expected call of Done
func (mr *MockAuthRequestIntMockRecorder) Done() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Done", reflect.TypeOf((*MockAuthRequestInt)(nil).Done))
}

// GetAccessConsumerServiceURL mocks base method
func (m *MockAuthRequestInt) GetAccessConsumerServiceURL() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAccessConsumerServiceURL")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAccessConsumerServiceURL indicates an expected call of GetAccessConsumerServiceURL
func (mr *MockAuthRequestIntMockRecorder) GetAccessConsumerServiceURL() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAccessConsumerServiceURL", reflect.TypeOf((*MockAuthRequestInt)(nil).GetAccessConsumerServiceURL))
}

// GetApplicationID mocks base method
func (m *MockAuthRequestInt) GetApplicationID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetApplicationID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetApplicationID indicates an expected call of GetApplicationID
func (mr *MockAuthRequestIntMockRecorder) GetApplicationID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetApplicationID", reflect.TypeOf((*MockAuthRequestInt)(nil).GetApplicationID))
}

// GetAuthRequestID mocks base method
func (m *MockAuthRequestInt) GetAuthRequestID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetAuthRequestID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetAuthRequestID indicates an expected call of GetAuthRequestID
func (mr *MockAuthRequestIntMockRecorder) GetAuthRequestID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAuthRequestID", reflect.TypeOf((*MockAuthRequestInt)(nil).GetAuthRequestID))
}

// GetBindingType mocks base method
func (m *MockAuthRequestInt) GetBindingType() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBindingType")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetBindingType indicates an expected call of GetBindingType
func (mr *MockAuthRequestIntMockRecorder) GetBindingType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBindingType", reflect.TypeOf((*MockAuthRequestInt)(nil).GetBindingType))
}

// GetCode mocks base method
func (m *MockAuthRequestInt) GetCode() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCode")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetCode indicates an expected call of GetCode
func (mr *MockAuthRequestIntMockRecorder) GetCode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCode", reflect.TypeOf((*MockAuthRequestInt)(nil).GetCode))
}

// GetDestination mocks base method
func (m *MockAuthRequestInt) GetDestination() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDestination")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetDestination indicates an expected call of GetDestination
func (mr *MockAuthRequestIntMockRecorder) GetDestination() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDestination", reflect.TypeOf((*MockAuthRequestInt)(nil).GetDestination))
}

// GetID mocks base method
func (m *MockAuthRequestInt) GetID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetID indicates an expected call of GetID
func (mr *MockAuthRequestIntMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockAuthRequestInt)(nil).GetID))
}

// GetIssuer mocks base method
func (m *MockAuthRequestInt) GetIssuer() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIssuer")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetIssuer indicates an expected call of GetIssuer
func (mr *MockAuthRequestIntMockRecorder) GetIssuer() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIssuer", reflect.TypeOf((*MockAuthRequestInt)(nil).GetIssuer))
}

// GetIssuerName mocks base method
func (m *MockAuthRequestInt) GetIssuerName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIssuerName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetIssuerName indicates an expected call of GetIssuerName
func (mr *MockAuthRequestIntMockRecorder) GetIssuerName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIssuerName", reflect.TypeOf((*MockAuthRequestInt)(nil).GetIssuerName))
}

// GetNameID mocks base method
func (m *MockAuthRequestInt) GetNameID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetNameID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetNameID indicates an expected call of GetNameID
func (mr *MockAuthRequestIntMockRecorder) GetNameID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetNameID", reflect.TypeOf((*MockAuthRequestInt)(nil).GetNameID))
}

// GetRelayState mocks base method
func (m *MockAuthRequestInt) GetRelayState() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRelayState")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetRelayState indicates an expected call of GetRelayState
func (mr *MockAuthRequestIntMockRecorder) GetRelayState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRelayState", reflect.TypeOf((*MockAuthRequestInt)(nil).GetRelayState))
}

// GetUserID mocks base method
func (m *MockAuthRequestInt) GetUserID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetUserID indicates an expected call of GetUserID
func (mr *MockAuthRequestIntMockRecorder) GetUserID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserID", reflect.TypeOf((*MockAuthRequestInt)(nil).GetUserID))
}

// GetUserName mocks base method
func (m *MockAuthRequestInt) GetUserName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetUserName indicates an expected call of GetUserName
func (mr *MockAuthRequestIntMockRecorder) GetUserName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserName", reflect.TypeOf((*MockAuthRequestInt)(nil).GetUserName))
}

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/tzrd/saml/pkg/provider (interfaces: IDPStorage)

// Package mock is a generated GoMock package.
package mock

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	key "github.com/tzrd/saml/pkg/provider/key"
	models "github.com/tzrd/saml/pkg/provider/models"
	serviceprovider "github.com/tzrd/saml/pkg/provider/serviceprovider"
	saml2p "github.com/tzrd/saml/pkg/provider/xml/saml2p"
	reflect "reflect"
)

// MockIDPStorage is a mock of IDPStorage interface
type MockIDPStorage struct {
	ctrl     *gomock.Controller
	recorder *MockIDPStorageMockRecorder
}

// MockIDPStorageMockRecorder is the mock recorder for MockIDPStorage
type MockIDPStorageMockRecorder struct {
	mock *MockIDPStorage
}

// NewMockIDPStorage creates a new mock instance
func NewMockIDPStorage(ctrl *gomock.Controller) *MockIDPStorage {
	mock := &MockIDPStorage{ctrl: ctrl}
	mock.recorder = &MockIDPStorageMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockIDPStorage) EXPECT() *MockIDPStorageMockRecorder {
	return m.recorder
}

// AuthRequestByID mocks base method
func (m *MockIDPStorage) AuthRequestByID(arg0 context.Context, arg1 string) (models.AuthRequestInt, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthRequestByID", arg0, arg1)
	ret0, _ := ret[0].(models.AuthRequestInt)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthRequestByID indicates an expected call of AuthRequestByID
func (mr *MockIDPStorageMockRecorder) AuthRequestByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthRequestByID", reflect.TypeOf((*MockIDPStorage)(nil).AuthRequestByID), arg0, arg1)
}

// CreateAuthRequest mocks base method
func (m *MockIDPStorage) CreateAuthRequest(arg0 context.Context, arg1 *saml2p.AuthnRequestType, arg2, arg3, arg4, arg5 string) (models.AuthRequestInt, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateAuthRequest", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(models.AuthRequestInt)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateAuthRequest indicates an expected call of CreateAuthRequest
func (mr *MockIDPStorageMockRecorder) CreateAuthRequest(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateAuthRequest", reflect.TypeOf((*MockIDPStorage)(nil).CreateAuthRequest), arg0, arg1, arg2, arg3, arg4, arg5)
}

// GetEntityByID mocks base method
func (m *MockIDPStorage) GetEntityByID(arg0 context.Context, arg1 string) (*serviceprovider.ServiceProvider, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEntityByID", arg0, arg1)
	ret0, _ := ret[0].(*serviceprovider.ServiceProvider)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEntityByID indicates an expected call of GetEntityByID
func (mr *MockIDPStorageMockRecorder) GetEntityByID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEntityByID", reflect.TypeOf((*MockIDPStorage)(nil).GetEntityByID), arg0, arg1)
}

// GetEntityIDByAppID mocks base method
func (m *MockIDPStorage) GetEntityIDByAppID(arg0 context.Context, arg1 string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetEntityIDByAppID", arg0, arg1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetEntityIDByAppID indicates an expected call of GetEntityIDByAppID
func (mr *MockIDPStorageMockRecorder) GetEntityIDByAppID(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetEntityIDByAppID", reflect.TypeOf((*MockIDPStorage)(nil).GetEntityIDByAppID), arg0, arg1)
}

// GetResponseSigningKey mocks base method
func (m *MockIDPStorage) GetResponseSigningKey(arg0 context.Context) (*key.CertificateAndKey, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetResponseSigningKey", arg0)
	ret0, _ := ret[0].(*key.CertificateAndKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetResponseSigningKey indicates an expected call of GetResponseSigningKey
func (mr *MockIDPStorageMockRecorder) GetResponseSigningKey(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetResponseSigningKey", reflect.TypeOf((*MockIDPStorage)(nil).GetResponseSigningKey), arg0)
}

// Health mocks base method
func (m *MockIDPStorage) Health(arg0 context.Context) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Health", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// Health indicates an expected call of Health
func (mr *MockIDPStorageMockRecorder) Health(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Health", reflect.TypeOf((*MockIDPStorage)(nil).Health), arg0)
}

// SetUserinfoWithLoginName mocks base method
func (m *MockIDPStorage) SetUserinfoWithLoginName(arg0 context.Context, arg1 models.AttributeSetter, arg2 string, arg3 []int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUserinfoWithLoginName", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUserinfoWithLoginName indicates an expected call of SetUserinfoWithLoginName
func (mr *MockIDPStorageMockRecorder) SetUserinfoWithLoginName(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUserinfoWithLoginName", reflect.TypeOf((*MockIDPStorage)(nil).SetUserinfoWithLoginName), arg0, arg1, arg2, arg3)
}

// SetUserinfoWithUserID mocks base method
func (m *MockIDPStorage) SetUserinfoWithUserID(arg0 context.Context, arg1 models.AttributeSetter, arg2 string, arg3 []int) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUserinfoWithUserID", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetUserinfoWithUserID indicates an expected call of SetUserinfoWithUserID
func (mr *MockIDPStorageMockRecorder) SetUserinfoWithUserID(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUserinfoWithUserID", reflect.TypeOf((*MockIDPStorage)(nil).SetUserinfoWithUserID), arg0, arg1, arg2, arg3)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: internal/domain/secret.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	io "io"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	domain "github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
)

// MockSecretService is a mock of SecretService interface.
type MockSecretService struct {
	ctrl     *gomock.Controller
	recorder *MockSecretServiceMockRecorder
}

// MockSecretServiceMockRecorder is the mock recorder for MockSecretService.
type MockSecretServiceMockRecorder struct {
	mock *MockSecretService
}

// NewMockSecretService creates a new mock instance.
func NewMockSecretService(ctrl *gomock.Controller) *MockSecretService {
	mock := &MockSecretService{ctrl: ctrl}
	mock.recorder = &MockSecretServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretService) EXPECT() *MockSecretServiceMockRecorder {
	return m.recorder
}

// CreateSecret mocks base method.
func (m *MockSecretService) CreateSecret(ctx context.Context, secret *domain.Secret, contentReader io.Reader) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateSecret", ctx, secret, contentReader)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateSecret indicates an expected call of CreateSecret.
func (mr *MockSecretServiceMockRecorder) CreateSecret(ctx, secret, contentReader interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateSecret", reflect.TypeOf((*MockSecretService)(nil).CreateSecret), ctx, secret, contentReader)
}

// DeleteSecret mocks base method.
func (m *MockSecretService) DeleteSecret(ctx context.Context, userID, secretName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteSecret", ctx, userID, secretName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSecret indicates an expected call of DeleteSecret.
func (mr *MockSecretServiceMockRecorder) DeleteSecret(ctx, userID, secretName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSecret", reflect.TypeOf((*MockSecretService)(nil).DeleteSecret), ctx, userID, secretName)
}

// GetLatestSecretByName mocks base method.
func (m *MockSecretService) GetLatestSecretByName(ctx context.Context, userID, secretName string) (*domain.Secret, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestSecretByName", ctx, userID, secretName)
	ret0, _ := ret[0].(*domain.Secret)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestSecretByName indicates an expected call of GetLatestSecretByName.
func (mr *MockSecretServiceMockRecorder) GetLatestSecretByName(ctx, userID, secretName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestSecretByName", reflect.TypeOf((*MockSecretService)(nil).GetLatestSecretByName), ctx, userID, secretName)
}

// GetLatestSecretStreamByName mocks base method.
func (m *MockSecretService) GetLatestSecretStreamByName(ctx context.Context, userID, secretName string) (*domain.Secret, io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestSecretStreamByName", ctx, userID, secretName)
	ret0, _ := ret[0].(*domain.Secret)
	ret1, _ := ret[1].(io.ReadCloser)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetLatestSecretStreamByName indicates an expected call of GetLatestSecretStreamByName.
func (mr *MockSecretServiceMockRecorder) GetLatestSecretStreamByName(ctx, userID, secretName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestSecretStreamByName", reflect.TypeOf((*MockSecretService)(nil).GetLatestSecretStreamByName), ctx, userID, secretName)
}

// GetSecretByVersion mocks base method.
func (m *MockSecretService) GetSecretByVersion(ctx context.Context, userID, secretName string, version int32) (*domain.Secret, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecretByVersion", ctx, userID, secretName, version)
	ret0, _ := ret[0].(*domain.Secret)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecretByVersion indicates an expected call of GetSecretByVersion.
func (mr *MockSecretServiceMockRecorder) GetSecretByVersion(ctx, userID, secretName, version interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecretByVersion", reflect.TypeOf((*MockSecretService)(nil).GetSecretByVersion), ctx, userID, secretName, version)
}

// GetSecretStreamByVersion mocks base method.
func (m *MockSecretService) GetSecretStreamByVersion(ctx context.Context, userID, secretName string, version int32) (*domain.Secret, io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecretStreamByVersion", ctx, userID, secretName, version)
	ret0, _ := ret[0].(*domain.Secret)
	ret1, _ := ret[1].(io.ReadCloser)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetSecretStreamByVersion indicates an expected call of GetSecretStreamByVersion.
func (mr *MockSecretServiceMockRecorder) GetSecretStreamByVersion(ctx, userID, secretName, version interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecretStreamByVersion", reflect.TypeOf((*MockSecretService)(nil).GetSecretStreamByVersion), ctx, userID, secretName, version)
}

// GetSecretsList mocks base method.
func (m *MockSecretService) GetSecretsList(ctx context.Context, userID string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecretsList", ctx, userID)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecretsList indicates an expected call of GetSecretsList.
func (mr *MockSecretServiceMockRecorder) GetSecretsList(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecretsList", reflect.TypeOf((*MockSecretService)(nil).GetSecretsList), ctx, userID)
}

// MockSecretRepository is a mock of SecretRepository interface.
type MockSecretRepository struct {
	ctrl     *gomock.Controller
	recorder *MockSecretRepositoryMockRecorder
}

// MockSecretRepositoryMockRecorder is the mock recorder for MockSecretRepository.
type MockSecretRepositoryMockRecorder struct {
	mock *MockSecretRepository
}

// NewMockSecretRepository creates a new mock instance.
func NewMockSecretRepository(ctrl *gomock.Controller) *MockSecretRepository {
	mock := &MockSecretRepository{ctrl: ctrl}
	mock.recorder = &MockSecretRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretRepository) EXPECT() *MockSecretRepositoryMockRecorder {
	return m.recorder
}

// CreateSecret mocks base method.
func (m *MockSecretRepository) CreateSecret(ctx context.Context, secret *domain.Secret) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateSecret", ctx, secret)
	ret0, _ := ret[0].(error)
	return ret0
}

// CreateSecret indicates an expected call of CreateSecret.
func (mr *MockSecretRepositoryMockRecorder) CreateSecret(ctx, secret interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateSecret", reflect.TypeOf((*MockSecretRepository)(nil).CreateSecret), ctx, secret)
}

// DeleteSecret mocks base method.
func (m *MockSecretRepository) DeleteSecret(ctx context.Context, userID, secretName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteSecret", ctx, userID, secretName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSecret indicates an expected call of DeleteSecret.
func (mr *MockSecretRepositoryMockRecorder) DeleteSecret(ctx, userID, secretName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSecret", reflect.TypeOf((*MockSecretRepository)(nil).DeleteSecret), ctx, userID, secretName)
}

// GetLatestSecretByName mocks base method.
func (m *MockSecretRepository) GetLatestSecretByName(ctx context.Context, userID, secretName string) (*domain.Secret, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetLatestSecretByName", ctx, userID, secretName)
	ret0, _ := ret[0].(*domain.Secret)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetLatestSecretByName indicates an expected call of GetLatestSecretByName.
func (mr *MockSecretRepositoryMockRecorder) GetLatestSecretByName(ctx, userID, secretName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetLatestSecretByName", reflect.TypeOf((*MockSecretRepository)(nil).GetLatestSecretByName), ctx, userID, secretName)
}

// GetSecretByVersion mocks base method.
func (m *MockSecretRepository) GetSecretByVersion(ctx context.Context, userID, secretName string, version int32) (*domain.Secret, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecretByVersion", ctx, userID, secretName, version)
	ret0, _ := ret[0].(*domain.Secret)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecretByVersion indicates an expected call of GetSecretByVersion.
func (mr *MockSecretRepositoryMockRecorder) GetSecretByVersion(ctx, userID, secretName, version interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecretByVersion", reflect.TypeOf((*MockSecretRepository)(nil).GetSecretByVersion), ctx, userID, secretName, version)
}

// GetSecretsList mocks base method.
func (m *MockSecretRepository) GetSecretsList(ctx context.Context, userID string) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSecretsList", ctx, userID)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSecretsList indicates an expected call of GetSecretsList.
func (mr *MockSecretRepositoryMockRecorder) GetSecretsList(ctx, userID interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSecretsList", reflect.TypeOf((*MockSecretRepository)(nil).GetSecretsList), ctx, userID)
}

// IsSecretExist mocks base method.
func (m *MockSecretRepository) IsSecretExist(ctx context.Context, userID, secretName string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsSecretExist", ctx, userID, secretName)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// IsSecretExist indicates an expected call of IsSecretExist.
func (mr *MockSecretRepositoryMockRecorder) IsSecretExist(ctx, userID, secretName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsSecretExist", reflect.TypeOf((*MockSecretRepository)(nil).IsSecretExist), ctx, userID, secretName)
}

// MockSecretObjectRepository is a mock of SecretObjectRepository interface.
type MockSecretObjectRepository struct {
	ctrl     *gomock.Controller
	recorder *MockSecretObjectRepositoryMockRecorder
}

// MockSecretObjectRepositoryMockRecorder is the mock recorder for MockSecretObjectRepository.
type MockSecretObjectRepositoryMockRecorder struct {
	mock *MockSecretObjectRepository
}

// NewMockSecretObjectRepository creates a new mock instance.
func NewMockSecretObjectRepository(ctrl *gomock.Controller) *MockSecretObjectRepository {
	mock := &MockSecretObjectRepository{ctrl: ctrl}
	mock.recorder = &MockSecretObjectRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretObjectRepository) EXPECT() *MockSecretObjectRepositoryMockRecorder {
	return m.recorder
}

// DeleteFile mocks base method.
func (m *MockSecretObjectRepository) DeleteFile(ctx context.Context, objectName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeleteFile", ctx, objectName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteFile indicates an expected call of DeleteFile.
func (mr *MockSecretObjectRepositoryMockRecorder) DeleteFile(ctx, objectName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteFile", reflect.TypeOf((*MockSecretObjectRepository)(nil).DeleteFile), ctx, objectName)
}

// ReadFileInChunks mocks base method.
func (m *MockSecretObjectRepository) ReadFileInChunks(ctx context.Context, objectName string) (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadFileInChunks", ctx, objectName)
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadFileInChunks indicates an expected call of ReadFileInChunks.
func (mr *MockSecretObjectRepositoryMockRecorder) ReadFileInChunks(ctx, objectName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadFileInChunks", reflect.TypeOf((*MockSecretObjectRepository)(nil).ReadFileInChunks), ctx, objectName)
}

// SaveFileInChunks mocks base method.
func (m *MockSecretObjectRepository) SaveFileInChunks(ctx context.Context, objectName string, contentReader io.Reader) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SaveFileInChunks", ctx, objectName, contentReader)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveFileInChunks indicates an expected call of SaveFileInChunks.
func (mr *MockSecretObjectRepositoryMockRecorder) SaveFileInChunks(ctx, objectName, contentReader interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveFileInChunks", reflect.TypeOf((*MockSecretObjectRepository)(nil).SaveFileInChunks), ctx, objectName, contentReader)
}

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen (interfaces: SecretService_CreateSecretStreamServer)

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
	metadata "google.golang.org/grpc/metadata"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// MockSecretService_CreateSecretStreamServer is a mock of SecretService_CreateSecretStreamServer interface.
type MockSecretService_CreateSecretStreamServer struct {
	ctrl     *gomock.Controller
	recorder *MockSecretService_CreateSecretStreamServerMockRecorder
}

// MockSecretService_CreateSecretStreamServerMockRecorder is the mock recorder for MockSecretService_CreateSecretStreamServer.
type MockSecretService_CreateSecretStreamServerMockRecorder struct {
	mock *MockSecretService_CreateSecretStreamServer
}

// NewMockSecretService_CreateSecretStreamServer creates a new mock instance.
func NewMockSecretService_CreateSecretStreamServer(ctrl *gomock.Controller) *MockSecretService_CreateSecretStreamServer {
	mock := &MockSecretService_CreateSecretStreamServer{ctrl: ctrl}
	mock.recorder = &MockSecretService_CreateSecretStreamServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSecretService_CreateSecretStreamServer) EXPECT() *MockSecretService_CreateSecretStreamServerMockRecorder {
	return m.recorder
}

// Context mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) Context() context.Context {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) Context() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Context", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).Context))
}

// Recv mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) Recv() (*pb.CreateSecretChunkRequest, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Recv")
	ret0, _ := ret[0].(*pb.CreateSecretChunkRequest)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Recv indicates an expected call of Recv.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) Recv() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Recv", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).Recv))
}

// RecvMsg mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) RecvMsg(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RecvMsg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecvMsg indicates an expected call of RecvMsg.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) RecvMsg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecvMsg", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).RecvMsg), arg0)
}

// SendAndClose mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) SendAndClose(arg0 *emptypb.Empty) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendAndClose", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendAndClose indicates an expected call of SendAndClose.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) SendAndClose(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendAndClose", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).SendAndClose), arg0)
}

// SendHeader mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) SendHeader(arg0 metadata.MD) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendHeader", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendHeader indicates an expected call of SendHeader.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) SendHeader(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendHeader", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).SendHeader), arg0)
}

// SendMsg mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) SendMsg(arg0 interface{}) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendMsg", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendMsg indicates an expected call of SendMsg.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) SendMsg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendMsg", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).SendMsg), arg0)
}

// SetHeader mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) SetHeader(arg0 metadata.MD) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetHeader", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetHeader indicates an expected call of SetHeader.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) SetHeader(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetHeader", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).SetHeader), arg0)
}

// SetTrailer mocks base method.
func (m *MockSecretService_CreateSecretStreamServer) SetTrailer(arg0 metadata.MD) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetTrailer", arg0)
}

// SetTrailer indicates an expected call of SetTrailer.
func (mr *MockSecretService_CreateSecretStreamServerMockRecorder) SetTrailer(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetTrailer", reflect.TypeOf((*MockSecretService_CreateSecretStreamServer)(nil).SetTrailer), arg0)
}

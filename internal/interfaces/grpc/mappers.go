package grpc

import (
	"github.com/ulixes-bloom/ya-gophkeeper/internal/domain"
	pb "github.com/ulixes-bloom/ya-gophkeeper/internal/infrastructure/proto/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mapProtoSecretTypeToDomain converts the gRPC SecretType to the domain's SecretType
func mapProtoSecretTypeToDomain(protoType pb.SecretType) domain.SecretType {
	switch protoType {
	case pb.SecretType_CREDENTIALS:
		return domain.CredentialsSecret
	case pb.SecretType_TEXT:
		return domain.TextSecret
	case pb.SecretType_BINARY:
		return domain.FileSecret
	case pb.SecretType_PAYMENT_CARD:
		return domain.PaymentCardSecret
	default:
		return ""
	}
}

// mapDomainSecretTypeToProto converts the domain SecretType to the corresponding gRPC SecretType
func mapDomainSecretTypeToProto(domainType domain.SecretType) pb.SecretType {
	switch domainType {
	case domain.CredentialsSecret:
		return pb.SecretType_CREDENTIALS
	case domain.TextSecret:
		return pb.SecretType_TEXT
	case domain.FileSecret:
		return pb.SecretType_BINARY
	case domain.PaymentCardSecret:
		return pb.SecretType_PAYMENT_CARD
	default:
		return -1
	}
}

// mapDomainSecretToProtoGetSecretInfoResponse converts the domain Secret object to a gRPC GetSecretInfoResponse
func mapDomainSecretToProtoGetSecretInfoResponse(secret *domain.Secret) *pb.GetSecretInfoResponse {
	return &pb.GetSecretInfoResponse{
		Name:      secret.Name,
		Metadata:  secret.Metadata,
		Type:      mapDomainSecretTypeToProto(secret.Type),
		Version:   secret.Version,
		CreatedAt: timestamppb.New(secret.CreatedAt),
	}
}

// mapProtoCreateSecretInfoRequestToDomainSecret converts the gRPC CreateSecretInfoRequest to a domain Secret
func mapProtoCreateSecretInfoRequestToDomainSecret(secretInfo *pb.CreateSecretInfoRequest, userID string) *domain.Secret {
	return &domain.Secret{
		Name:     secretInfo.GetName(),
		UserID:   userID,
		Type:     mapProtoSecretTypeToDomain(secretInfo.GetType()),
		Metadata: secretInfo.GetMetadata(),
	}
}

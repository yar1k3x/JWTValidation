package middleware

import (
	"context"
	"strings"

	"github.com/yar1k3x/JWTValidation/jwt" // 🔁 твой валидатор токена

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func AuthMiddleware(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	authHeaders := md["authorization"]
	if len(authHeaders) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization header required")
	}

	const prefix = "Bearer "
	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, prefix) {
		return nil, status.Errorf(codes.Unauthenticated, "invalid auth header format")
	}
	tokenStr := strings.TrimPrefix(authHeader, prefix)

	_, err := jwt.ValidateJWT(tokenStr)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "token invalid: %v", err)
	}

	// Можно сохранить userID в context для использования в handler'ах
	//ctx = context.WithValue(ctx, "userID", claims.Subject)

	return ctx, nil
}

package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var JWTSecretKey string

func GenerateJWT(userID string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JWTSecretKey)
}

func ValidateJWT(tokenStr string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Проверяем, что алгоритм — HMAC (HS256, HS384, HS512)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		// Если у тебя JWTSecretKey — строка, то конвертируем в []byte:
		return []byte(JWTSecretKey), nil
	})
	if err != nil {
		return nil, err
	}

	// Проверяем валидность и приводим claims
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

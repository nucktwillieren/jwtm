package jwtm

import (
	"errors"
	"reflect"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrTokenInvalid = errors.New("token is invalid")

	ErrTokenExpired = errors.New("token is expired")

	ErrTokenMalformed = errors.New("token is malformed")

	ErrTokenNotValidYet = errors.New("token is not valid yet")

	ErrTokenUnverifiable = errors.New("token could not be verified because of signing problems")

	ErrTokenSignatureValidation = errors.New("signature validation failed")

	ErrCannotHandle = errors.New("cannot handle this problem")
)

type Manager interface {
	NewToken(claims jwt.Claims) (string, error)
	ParseAndVerify(token string, claims jwt.Claims) (jwt.Claims, error)
}

type manager struct {
	method     jwt.SigningMethod
	signingKey interface{}
	verifyKey  interface{}
}

func NewManger(method jwt.SigningMethod, signingKey interface{}, verifyKey interface{}) Manager {
	return &manager{
		method:     method,
		signingKey: signingKey,
		verifyKey:  verifyKey,
	}
}

func (m *manager) NewToken(claims jwt.Claims) (string, error) {
	tokenClaims := jwt.NewWithClaims(
		m.method,
		claims,
	)

	token, err := tokenClaims.SignedString(m.signingKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (m *manager) ParseAndVerify(token string, claims jwt.Claims) (jwt.Claims, error) {
	t := reflect.ValueOf(claims).Type().Elem()
	claimsObj := reflect.New(t).Interface().(jwt.Claims)

	tokenClaims, err := jwt.ParseWithClaims(token, claimsObj, func(token *jwt.Token) (i interface{}, err error) {
		return m.verifyKey, nil
	})

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return claimsObj, ErrTokenMalformed
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				return claimsObj, ErrTokenUnverifiable
			} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return claimsObj, ErrTokenSignatureValidation
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return claimsObj, ErrTokenExpired
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return claimsObj, ErrTokenNotValidYet
			}
		}
		return claims, ErrCannotHandle
	}

	if !tokenClaims.Valid {
		return claimsObj, ErrTokenInvalid
	}

	return tokenClaims.Claims, nil
}

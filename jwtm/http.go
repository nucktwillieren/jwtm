package jwtm

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CookieOptions struct {
	Path    string    // optional
	Domain  string    // optional
	Expires time.Time // optional

	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

func (c *CookieOptions) makeNew(name string, value string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     c.Path,
		Domain:   c.Domain,
		Expires:  c.Expires,
		MaxAge:   c.MaxAge,
		Secure:   c.Secure,
		HttpOnly: c.HttpOnly,
		SameSite: c.SameSite,
	}
}

type HttpTokenExtractor func(c context.Context, req *http.Request) string

type HttpTokenWriter func(c context.Context, w http.ResponseWriter, token string) error

func MakeCookieTokenExtractor(cookieName string) HttpTokenExtractor {
	return func(c context.Context, req *http.Request) string {
		cookieToken, err := req.Cookie(cookieName)
		if err != nil {
			return ""
		}

		return cookieToken.Value
	}
}

func MakeCookieTokenWriter(cookieName string, cookieOptions CookieOptions) HttpTokenWriter {
	return func(c context.Context, w http.ResponseWriter, token string) error {
		cookieToken := cookieOptions.makeNew(cookieName, token)

		http.SetCookie(w, cookieToken)

		return nil
	}
}

func MakeHeaderTokenExtractor(headerName string, tokenType string) HttpTokenExtractor {
	return func(c context.Context, req *http.Request) string {
		headerToken := req.Header.Get(headerName)

		sep := strings.Split(headerToken, " ")

		if len(sep) != 2 || !strings.EqualFold(sep[0], tokenType) {
			return ""
		}

		return sep[1]
	}
}

func MakeHeaderTokenWriter(headerName string, tokenType string) HttpTokenWriter {
	return func(c context.Context, w http.ResponseWriter, token string) error {
		headerToken := fmt.Sprintf("%s %s", tokenType, token)

		w.Header().Add(headerName, headerToken)

		return nil
	}
}

package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"time"
)

const (
	csrfCookieName = "csrf_token"
	csrfHeader     = "X-CSRF-Token"
)

type CSRF struct {
	key []byte
}

func New() *CSRF {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return &CSRF{key}
}

func (c *CSRF) GenerateToken() string {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(token)
}

func (c *CSRF) SetCookie(w http.ResponseWriter, token string) {
	cookie := http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		Expires:  time.Now().Add(time.Hour * 1),
		SameSite: http.SameSiteDefaultMode,
	}
	http.SetCookie(w, &cookie)
}

func (c *CSRF) GetCookie(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (c *CSRF) VerifyToken(r *http.Request) bool {
	token := c.GetCookie(r)
	if token == "" {
		return false
	}

	headerToken := r.Header.Get(csrfHeader)
	if headerToken == "" {
		return false
	}

	return c.IsValid(token, headerToken)
}

func (c *CSRF) IsValid(token, headerToken string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(headerToken)) == 1
}

func (c *CSRF) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// validate CSRF tokens on any HTTP methods that make state-changing requests, such as POST, PUT, PATCH, and DELETE.
		if r.Method == http.MethodPost ||
			r.Method == http.MethodPut ||
			r.Method == http.MethodPatch ||
			r.Method == http.MethodDelete {

			if c.VerifyToken(r) {
				next.ServeHTTP(w, r)
				return
			}

			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		}

		// HTTP methods that only retrieve data, such as GET, HEAD, and OPTIONS, do not typically require CSRF token validation
		next.ServeHTTP(w, r)
		return
	})
}

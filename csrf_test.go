package csrf

import (
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCSRFTokenGeneration(t *testing.T) {
	csrf := New()
	token1 := csrf.GenerateToken()
	token2 := csrf.GenerateToken()
	if token1 == token2 {
		t.Errorf("Generated tokens should not be the same")
	}
}

func TestFlowInjectCookie(t *testing.T) {
	csrf := New()
	token := csrf.GenerateToken()

	mux := http.NewServeMux()
	mux.Handle("/", csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csrf.SetCookie(w, token)
	})))

	mux.Handle("/post", csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})))

	req, err := http.NewRequest(http.MethodGet, "/", nil)

	if err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Errorf("unable to do GET request")
	}

	if len(res.Result().Cookies()) == 0 {
		t.Fatal("no cookie is set")
	}

	if res.Result().Cookies()[0].Value != token {
		t.Error("cookie mismatch")
	}

	req, err = http.NewRequest(http.MethodPost, "/post", nil)
	if err != nil {
		t.Fatal(err)
	}

	// inject cookie from previous response in the new request
	req.AddCookie(res.Result().Cookies()[0])

	// set X-CSRF-Token in request
	req.Header.Set("X-CSRF-Token", token)

	mux.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatal("csrf failed but should pass")
	}
}

func TestFlowCookieJar(t *testing.T) {
	csrf := New()
	token := csrf.GenerateToken()

	mux := http.NewServeMux()
	mux.Handle("/", csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		csrf.SetCookie(w, token)
	})))

	mux.Handle("/post", csrf.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	})))

	ts := httptest.NewServer(mux)
	defer ts.Close()

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Jar: jar,
	}

	u, err := url.Parse(ts.URL)
	if err != nil {
		log.Fatal(err)
	}

	if _, err = client.Get(u.String()); err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, u.String()+"/post", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-CSRF-Token", token)

	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if res.StatusCode != http.StatusOK {
		t.Fatal("csrf failed but should pass")
	}
}

func TestCSRFMiddleware(t *testing.T) {
	csrf := New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})
	mux := http.NewServeMux()
	mux.Handle("/", csrf.Middleware(handler))
	req, err := http.NewRequest("POST", "/", nil)

	if err != nil {
		t.Fatal(err)
	}
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Errorf("CSRF middleware did not reject request")
	}
}

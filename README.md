# go-csrf


Basic CSRF handling in golang. There are quite a few versions on csrf handling, but I needed something to cover the bare minimum.

```go
package example 

import (
	"net/http"
	
	"github.com/donseba/go-csrf"
)

func exampleFormHandler(w http.ResponseWriter, r *http.Request) {
    c := csrf.New()
    // the token should be generated on the page that invokes the form
    token := c.GenerateToken()
    
    // in this example we are going to set the csrf token into a cookie 
    // you could also pass the token to the form to post the token, and store the token in a session handler.
    // most session handlers however also use a cookie with (no)sql backend.
    c.SetCookie(w,token)
    
    // use the middleware. which can be called using `csrf.New().Middleware()` and wrap it 
    // around the handler(s) that need validation. Easiest way is to use it at the root. 
    // with chi you can do this. 
    r := chi.NewRouter()
    r.Use(csrf.New().Middleware)
}

```



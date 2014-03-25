package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"labix.org/v2/mgo"

	"github.com/juju/affinity"
	"github.com/juju/affinity/examples"
	"github.com/juju/affinity/providers/usso"
	"github.com/juju/affinity/rbac"
	rbac_mongo "github.com/juju/affinity/storage/mongo"
)

const dataDir = "./"

var mgoAddr *string = flag.String("mongo", "localhost:27017", "Mongo DB URL")
var mgoDbName *string = flag.String("dbname", "demo", "Mongo DB name")
var certFile *string = flag.String("cert", "cert.pem", "SSL certificate")
var keyFile *string = flag.String("key", "key.pem", "SSL private key")

type DemoHandler struct {
	Store  rbac.Store
	Scheme affinity.HandshakeScheme
}

func die(err error) {
	log.Println(err)
	os.Exit(1)
}

func main() {
	flag.Parse()

	// affinity only redirects to https:// URLs for OpenID.
	// We'll create some self-signed certs for the demo if needed.
	err := examples.BuildCerts(*keyFile, *certFile, "localhost:8443")
	if err != nil {
		die(err)
	}

	session, err := mgo.Dial(*mgoAddr)
	if err != nil {
		die(fmt.Errorf("Failed to connect to store:%v", err))
	}

	rbacStore, err := rbac_mongo.NewMongoStore(session, *mgoDbName, "","")
	if err != nil {
		die(fmt.Errorf("Failed to find store:%v", err))
	}

	sessionStore := sessions.NewCookieStore(
		securecookie.GenerateRandomKey(32),
		securecookie.GenerateRandomKey(32),
	)

	demoContext := DemoHandler{
		Store:  rbacStore,
		Scheme: usso.NewOpenIdWeb("openid-demo", "", sessionStore),
	}

	r := mux.NewRouter()
	r.Handle("/", HomeHandler{&demoContext})
	r.Handle("/login", LoginHandler{&demoContext})
	r.Handle("/openidcallback", CallbackHandler{&demoContext})

	// Send all incoming requests to mux.DefaultRouter.
	go http.ListenAndServe(":8080", RedirectToTls{})
	err = http.ListenAndServeTLS(":8443", *certFile, *keyFile, r)
	if err != nil {
		die(err)
	}
}

type RedirectToTls struct{}

func (_ RedirectToTls) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	http.Redirect(w, req, fmt.Sprintf("https://%v:8443%v", host, req.URL.Path), 301)
}

func BadRequest(w http.ResponseWriter, err error) {
	log.Println(err)
}

type HomeHandler struct {
	*DemoHandler
}

func (h HomeHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")

	p := make(map[string]string)
	user, err := h.Scheme.Authenticate(req)
	if err != nil {
		if err != affinity.ErrUnauthorized {
			log.Println("Warning: authenticate error:", err)
			BadRequest(w, err)
			return
		}
	} else {
		p["user"] = user.String()
	}
	if t, err := template.ParseFiles(dataDir + "index.html"); err == nil {
		t.Execute(w, p)
	} else {
		BadRequest(w, err)
	}
}

type LoginHandler struct {
	*DemoHandler
}

func (h LoginHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	_, err := h.Scheme.Authenticate(req)
	if err != nil {
		if err != affinity.ErrUnauthorized {
			log.Println("Warning: authenticate error:", err)
			BadRequest(w, err)
			return
		}
		err = h.Scheme.SignIn(w, req)
		if err != nil {
			log.Println("Warning: Sign in error:", err)
			BadRequest(w, err)
		}
		// SignIn will have written a redirect if successful.
		return
	}
	// What are we doing here if we're logged in?
	http.Redirect(w, req, "/", 303)
}

type CallbackHandler struct {
	*DemoHandler
}

func (h CallbackHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.Scheme.Authenticated(w, req)
}

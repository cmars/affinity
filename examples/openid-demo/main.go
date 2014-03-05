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
	Store          rbac.Store
	Scheme         affinity.Scheme
	CurrentUser    affinity.User
	CurrentDetails *affinity.TokenInfo
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

	rbacStore, err := rbac_mongo.NewMongoStore(session, *mgoDbName)
	if err != nil {
		die(fmt.Errorf("Failed to find store:%v", err))
	}

	demoContext := DemoHandler{
		Store:          rbacStore,
		Scheme:         usso.NewOpenIdWeb("openid-demo@localhost"),
		CurrentUser:    affinity.User{},
		CurrentDetails: &affinity.TokenInfo{},
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
	p["user"] = h.CurrentUser.Id
	log.Println("User details from OpenID authentication:", h.CurrentDetails.Serialize())
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
	if h.Scheme.Authenticator().Authenticate(w, req) {
		http.Redirect(w, req, "/", 303)
		return
	}
}

type CallbackHandler struct {
	*DemoHandler
}

func (h CallbackHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	h.CurrentUser, h.CurrentDetails, err = h.Scheme.Authenticator().Callback(w, req)
	if err != nil {
		log.Println("OpenID callback error:", err)
	}
	log.Println("User details from OpenID authentication:", h.CurrentDetails)
}

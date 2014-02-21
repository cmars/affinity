package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	"github.com/juju/affinity"
	"github.com/juju/affinity/providers/usso"
	rbac_mongo "github.com/juju/affinity/storage/mongo"
	"labix.org/v2/mgo"
)

const dataDir = "./"

var mgoAddr *string = flag.String("mongo", "localhost:27017", "Mongo DB URL")
var mgoDbName *string = flag.String("dbname", "demo", "Mongo DB name")

type DemoHandler struct {
	Store          affinity.Store
	Scheme         affinity.Scheme
	CurrentUser    affinity.User
	CurrentDetails url.Values
}

func die(err error) {
	log.Println(err)
	os.Exit(1)
}

func main() {
	session, err := mgo.Dial(*mgoAddr)
	if err != nil {
		die(fmt.Errorf("Failed to connect to store:%v", err))
	}

	rbacStore, err := rbac_mongo.NewMongoStore(session, *mgoDbName)
	if err != nil {
		die(fmt.Errorf("Failed to find store:%v", err))
	}

	demoContext := DemoHandler{
		Store:       rbacStore,
		Scheme:      usso.NewScheme("localhost"),
		CurrentUser: affinity.User{},
	}

	r := mux.NewRouter()
	r.Handle("/", HomeHandler{&demoContext})
	r.Handle("/login", LoginHandler{&demoContext})
	r.Handle("/openidcallback", CallbackHandler{&demoContext})

	// Send all incoming requests to mux.DefaultRouter.
	http.ListenAndServe(":8080", r)
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
}

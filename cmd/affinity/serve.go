package main

import (
	"log"
	"net/http"

	"launchpad.net/gnuflag"

	. "github.com/cmars/affinity/server"
	"github.com/cmars/affinity/usso"
)

type serveCmd struct {
	subCmd
	addr  string
	token string
}

func newServeCmd() *serveCmd {
	cmd := &serveCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.addr, "http", "", "Listen address")
	cmd.flags.StringVar(&cmd.token, "token", "affinity", "Token name used for OAuth schemes")
	return cmd
}

func (c *serveCmd) Name() string { return "serve" }

func (c *serveCmd) Desc() string { return "Run the affinity server" }

func (c *serveCmd) Main() {
	s := NewServer(NewTestStore())
	s.RegisterScheme(&usso.UssoScheme{Token: c.token})
	err := http.ListenAndServe(c.addr, s)
	log.Println(err)
}

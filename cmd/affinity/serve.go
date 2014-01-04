/*
   Affinity - Private groups as a service
   Copyright (C) 2014  Canonical, Ltd.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"net/http"

	"launchpad.net/gnuflag"

	. "github.com/cmars/affinity/server"
	"github.com/cmars/affinity/server/mongo"
	"github.com/cmars/affinity/usso"
)

type serveCmd struct {
	subCmd
	addr  string
	token string
	mongo string
}

func newServeCmd() *serveCmd {
	cmd := &serveCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.addr, "http", "", "Listen address")
	cmd.flags.StringVar(&cmd.mongo, "mongo", "localhost:27017", "MongoDB URL")
	cmd.flags.StringVar(&cmd.token, "token", "affinity", "Token name used for OAuth schemes")
	return cmd
}

func (c *serveCmd) Name() string { return "serve" }

func (c *serveCmd) Desc() string { return "Run the affinity server" }

func (c *serveCmd) Main() {
	store, err := mongo.NewMongoStore(c.mongo)
	if err != nil {
		die(err)
	}
	s := NewServer(store)
	s.RegisterScheme(&usso.UssoScheme{Token: c.token})
	err = http.ListenAndServe(c.addr, s)
	die(err)
}

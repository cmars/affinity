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

	"labix.org/v2/mgo"
	"launchpad.net/gnuflag"

	"launchpad.net/go-affinity/providers/usso"
	. "launchpad.net/go-affinity/server"
	"launchpad.net/go-affinity/server/mongo"
)

type serveCmd struct {
	subCmd
	addr    string
	extName string
	mongo   string
	dbname  string
}

func newServeCmd() *serveCmd {
	cmd := &serveCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.addr, "http", ":8080", "Listen address")
	cmd.flags.StringVar(&cmd.extName, "name", "", "External server hostname")
	cmd.flags.StringVar(&cmd.mongo, "mongo", "localhost:27017", "MongoDB URL")
	cmd.flags.StringVar(&cmd.dbname, "database", "affinity", "Mongo database name")
	return cmd
}

func (c *serveCmd) Name() string { return "serve" }

func (c *serveCmd) Desc() string { return "Run the affinity server" }

func (c *serveCmd) Main() {
	if c.extName == "" {
		Usage(c, "--name is required")
	}
	session, err := mgo.Dial(c.mongo)
	if err != nil {
		die(err)
	}
	store, err := mongo.NewMongoStore(session, c.dbname)
	if err != nil {
		die(err)
	}
	s := NewServer(store)
	s.RegisterScheme(usso.NewScheme(c.extName))
	err = http.ListenAndServe(c.addr, s)
	die(err)
}

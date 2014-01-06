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
	"github.com/cmars/affinity/providers/usso"
)

type serveCmd struct {
	subCmd
	addr    string
	extName string
	mongo   string
}

func newServeCmd() *serveCmd {
	cmd := &serveCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.addr, "http", ":8080", "Listen address")
	cmd.flags.StringVar(&cmd.extName, "name", "", "External server hostname")
	cmd.flags.StringVar(&cmd.mongo, "mongo", "localhost:27017", "MongoDB URL")
	return cmd
}

func (c *serveCmd) Name() string { return "serve" }

func (c *serveCmd) Desc() string { return "Run the affinity server" }

func (c *serveCmd) Main() {
	if c.extName == "" {
		Usage(c, "--name is required")
	}
	store, err := mongo.NewMongoStore(c.mongo)
	if err != nil {
		die(err)
	}
	s := NewServer(store)
	s.RegisterScheme(usso.NewScheme(c.extName))
	err = http.ListenAndServe(c.addr, s)
	die(err)
}

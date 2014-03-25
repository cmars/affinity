/*
   Affinity - Private groups as a service
   Copyright (C) 2014  Canonical, Ltd.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Library General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"log"
	"net/http"
	"strings"

	"labix.org/v2/mgo"
	"launchpad.net/gnuflag"

	"github.com/juju/affinity"
	"github.com/juju/affinity/group"
	"github.com/juju/affinity/providers/usso"
	"github.com/juju/affinity/rbac"
	. "github.com/juju/affinity/server/group"
	"github.com/juju/affinity/storage/mongo"
)

type serveCmd struct {
	subCmd
	addr            string
	extName         string
	mongo           string
	dbname          string
	serviceAdminCsv string

	serviceAdmins []string
}

func newServeCmd() *serveCmd {
	cmd := &serveCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.addr, "http", ":8080", "Listen address")
	cmd.flags.StringVar(&cmd.extName, "name", "", "External server hostname")
	cmd.flags.StringVar(&cmd.mongo, "mongo", "localhost:27017", "MongoDB URL")
	cmd.flags.StringVar(&cmd.dbname, "database", "affinity", "Mongo database name")
	cmd.flags.StringVar(&cmd.serviceAdminCsv, "service-admins", "",
		"Users granted service management role")
	return cmd
}

func (c *serveCmd) Name() string { return "serve" }

func (c *serveCmd) Desc() string { return "Run the affinity server" }

func (c *serveCmd) Main() {
	if c.extName == "" {
		Usage(c, "--name is required")
	}

	c.serviceAdmins = strings.Split(c.serviceAdminCsv, ",")
	for i := range c.serviceAdmins {
		c.serviceAdmins[i] = strings.TrimSpace(c.serviceAdmins[i])
	}

	session, err := mgo.Dial(c.mongo)
	if err != nil {
		die(err)
	}
	store, err := mongo.NewMongoStore(session, c.dbname, "", "")
	if err != nil {
		die(err)
	}

	s := NewGroupServer(store)

	// Grant service role to configured admins
	for _, serviceAdmin := range c.serviceAdmins {
		admin := rbac.NewAdmin(store, group.GroupRoles)
		u, err := affinity.ParseUser(serviceAdmin)
		if err != nil {
			die(err)
		}
		err = admin.Grant(u, group.ServiceRole, group.ServiceResource)
		if err != nil {
			log.Println("Warning:", err)
		}
	}

	s.Schemes.Register(usso.NewOauthCli(c.extName, &affinity.PasswordUnavailable{}))
	err = http.ListenAndServe(c.addr, s)
	die(err)
}

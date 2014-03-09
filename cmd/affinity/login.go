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
	"fmt"
	"net/url"
	"os"
	"path"

	"launchpad.net/gnuflag"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/client"
	"github.com/juju/affinity/providers/usso"
)

type loginCmd struct {
	subCmd
	url     string
	user    string
	homeDir string
}

func newLoginCmd() *loginCmd {
	cmd := &loginCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.url, "url", "", "Affinity server URL")
	cmd.flags.StringVar(&cmd.user, "user", "", "Authenticate user")
	cmd.flags.StringVar(&cmd.homeDir, "homedir", "", "Affinity client home (default: ~/.affinity)")
	return cmd
}

func (c *loginCmd) Name() string { return "login" }

func (c *loginCmd) Desc() string { return "Log in to generate an affinity credential" }

func (c *loginCmd) Main() {
	schemes := NewSchemeMap()

	if c.url == "" {
		Usage(c, "--url is required")
	}
	if c.user == "" {
		Usage(c, "--user is required")
	}
	if c.homeDir == "" {
		c.homeDir = path.Join(os.Getenv("HOME"), ".affinity")
	}

	serverUrl, err := url.Parse(c.url)
	if err != nil {
		die(err)
	}
	schemes.Register(usso.NewOauthCli(fmt.Sprintf("affinity@%s", serverUrl.Host),
		&PasswordPrompter{}))

	user, err := ParseUser(c.user)
	if err != nil {
		die(err)
	}

	scheme := schemes.Token(user.Scheme)
	if scheme == nil {
		die(fmt.Errorf("Scheme '%s' is not supported", user.Scheme))
	}

	token, err := scheme.Authorize(user)
	if err != nil {
		die(err)
	}

	authStore, err := client.NewFileAuthStore(c.homeDir)
	if err != nil {
		die(err)
	}

	err = authStore.Set(token, serverUrl.Host)
	if err != nil {
		die(err)
	}
}

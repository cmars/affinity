package main

import (
	"fmt"
	"os"
	"path"

	"launchpad.net/gnuflag"

	. "github.com/cmars/affinity"
	"github.com/cmars/affinity/usso"
)

type loginCmd struct {
	subCmd
	token   string
	user    string
	homeDir string
}

func newLoginCmd() *loginCmd {
	cmd := &loginCmd{}
	cmd.flags = gnuflag.NewFlagSet(cmd.Name(), gnuflag.ExitOnError)
	cmd.flags.StringVar(&cmd.token, "token", "affinity", "Token name used for OAuth schemes")
	cmd.flags.StringVar(&cmd.user, "user", "", "Authenticate user")
	cmd.flags.StringVar(&cmd.homeDir, "homedir", "", "Affinity client home (default: ~/.affinity)")
	return cmd
}

func (c *loginCmd) Name() string { return "login" }

func (c *loginCmd) Desc() string { return "Log in to generate an affinity credential" }

func (c *loginCmd) Main() {
	schemes := make(SchemeMap)
	schemes.Register(&usso.UssoScheme{Token: c.token})

	if c.user == "" {
		Usage(c, "User is required")
	}
	if c.homeDir == "" {
		c.homeDir = path.Join(os.Getenv("HOME"), ".affinity")
	}

	user, err := ParseUser(c.user)
	if err != nil {
		die(err)
	}

	scheme, has := schemes[user.Scheme]
	if !has {
		die(fmt.Errorf("Scheme '%s' is not supported", user.Scheme))
	}

	values, err := scheme.Authorizer().Auth(user.Id)
	if err != nil {
		die(err)
	}

	err = os.MkdirAll(c.homeDir, 0700)
	if err != nil {
		die(err)
	}

	authFile := path.Join(c.homeDir, "auth")
	f, err := os.OpenFile(authFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		die(err)
	}
	defer f.Close()
	fmt.Fprintln(f, values.Encode())
}

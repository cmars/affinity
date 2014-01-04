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
	"fmt"
	"os"
	"path/filepath"

	"launchpad.net/gnuflag"
)

func die(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

type cmdHandler interface {
	Name() string
	Desc() string
	Flags() *gnuflag.FlagSet
	Main()
}

type subCmd struct {
	flags *gnuflag.FlagSet
}

func (c subCmd) Flags() *gnuflag.FlagSet { return c.flags }

func Usage(h cmdHandler, msg string) {
	fmt.Fprintln(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "\n  %s %s\t\t%s\n\n",
		filepath.Base(os.Args[0]), h.Name(), h.Desc())
	if h.Flags() != nil {
		h.Flags().PrintDefaults()
	}
	os.Exit(1)
}

var cmds []cmdHandler = []cmdHandler{
	newServeCmd(),
	newLoginCmd(),
	newAddGroupCmd(),
	newRemoveGroupCmd(),
	newShowGroupCmd(),
	newAddUserCmd(),
	newRemoveUserCmd(),
	newCheckUserCmd(),
}

func main() {
	if len(os.Args) < 2 {
		newHelpCmd().Main()
		return
	}
	var cmdArgs []string
	if len(os.Args) > 2 {
		cmdArgs = os.Args[2:]
	}
	for _, cmd := range cmds {
		if cmd.Name() == os.Args[1] {
			if flags := cmd.Flags(); flags != nil {
				flags.Parse(false, cmdArgs)
			}
			cmd.Main()
			return
		}
	}
	newHelpCmd().Main()
}

type helpCmd struct {
	subCmd
}

func (c *helpCmd) Name() string { return "help" }

func (c *helpCmd) Desc() string { return "Display this help message" }

func (c *helpCmd) Main() {
	fmt.Fprintln(os.Stderr, `Affinity -- User groups as a service
https://github.com/cmars/affinity

Affinity is a simple HTTP API that users to create and administer
private groups of authenticated users for any purpose. Groups are
defined by a well-known URI which can be referened by applications,
if they are granted access to the group.

Basic commands:
`)
	for _, cmd := range cmds {
		fmt.Fprintf(os.Stderr, "  %s %s\t\t%s\n",
			filepath.Base(os.Args[0]), cmd.Name(), cmd.Desc())
	}
	os.Exit(1)
}

func newHelpCmd() *helpCmd {
	return new(helpCmd)
}

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

package group

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/client"
)

type GroupClient struct {
	*client.AuthClient

	Url url.URL
}

func NewGroupClient(u *url.URL, authStore client.AuthStore) *GroupClient {
	return &GroupClient{
		AuthClient: &client.AuthClient{
			Client: http.DefaultClient,
			Store:  authStore,
		},
		Url: *u,
	}
}

func (c *GroupClient) AddGroup(group string) error {
	_, err := c.doGroupRequest(group, "PUT")
	return err
}

func (c *GroupClient) DeleteGroup(group string) error {
	_, err := c.doGroupRequest(group, "DELETE")
	return err
}

func (c *GroupClient) GetGroup(group string) (g Group, err error) {
	out, err := c.doGroupRequest(group, "GET")
	if err != nil {
		return g, err
	}
	err = json.Unmarshal(out, &g)
	return g, err
}

func (c *GroupClient) doGroupRequest(group string, method string) ([]byte, error) {
	var u url.URL
	u = c.Url
	u.Path = fmt.Sprintf("/%v/", group)
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.AuthClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	return buf.Bytes(), err
}

func (c *GroupClient) AddUser(group string, user User) error {
	_, err := c.doUserRequest(group, user, "PUT")
	return err
}

func (c *GroupClient) DeleteUser(group string, user User) error {
	_, err := c.doUserRequest(group, user, "DELETE")
	return err
}

func (c *GroupClient) CheckUser(group string, user User) error {
	_, err := c.doUserRequest(group, user, "GET")
	return err
}

func (c *GroupClient) doUserRequest(group string, user User, method string) ([]byte, error) {
	var u url.URL
	u = c.Url
	u.Path = fmt.Sprintf("/%v/%v/", group, user.String())
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.AuthClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf(resp.Status)
	}
	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	return buf.Bytes(), err
}

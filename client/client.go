package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	. "github.com/cmars/affinity"
)

type Client struct {
	Auth string
	Url  string

	schemes SchemeMap
}

func (c *Client) RegisterScheme(s Scheme) {
	c.schemes[s.Name()] = s
}

func (c *Client) AddGroup(group string) error {
	_, err := c.doGroupRequest(group, "PUT")
	return err
}

func (c *Client) DeleteGroup(group string) error {
	_, err := c.doGroupRequest(group, "DELETE")
	return err
}

func (c *Client) GetGroup(group string) (g Group, err error) {
	out, err := c.doGroupRequest(group, "GET")
	if err != nil {
		return g, err
	}
	err = json.Unmarshal(out, &g)
	return g, err
}

func (c *Client) doGroupRequest(group string, method string) ([]byte, error) {
	u, err := url.Parse(c.Url)
	if err != nil {
		return nil, err
	}
	u.Path = fmt.Sprintf("/%v", group)
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", c.Auth)
	resp, err := http.DefaultClient.Do(req)
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

func (c *Client) AddUser(group string, user User) error {
	_, err := c.doUserRequest(group, user, "PUT")
	return err
}

func (c *Client) DeleteUser(group string, user User) error {
	_, err := c.doUserRequest(group, user, "DELETE")
	return err
}

func (c *Client) CheckUser(group string, user User) error {
	_, err := c.doUserRequest(group, user, "GET")
	return err
}

func (c *Client) doUserRequest(group string, user User, method string) ([]byte, error) {
	u, err := url.Parse(c.Url)
	if err != nil {
		return nil, err
	}
	u.Path = fmt.Sprintf("/%s/%s", group, user.String())
	req, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", c.Auth)
	resp, err := http.DefaultClient.Do(req)
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

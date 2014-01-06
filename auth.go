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

package affinity

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
)

type FileAuthStore struct {
	homeDir  string
	url      *url.URL
	authFile string
}

func NewFileAuthStore(homeDir string, u *url.URL) (*FileAuthStore, error) {
	dir := path.Join(homeDir, u.Host)
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		return nil, err
	}
	authFile := path.Join(dir, "auth")
	return &FileAuthStore{dir, u, authFile}, nil
}

func (s *FileAuthStore) Read() (url.Values, error) {
	authContents, err := ioutil.ReadFile(s.authFile)
	if err != nil {
		return nil, err
	}
	auth := strings.TrimSpace(string(authContents))
	return url.ParseQuery(auth)
}

func (s *FileAuthStore) Write(values url.Values) error {
	f, err := os.OpenFile(s.authFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, values.Encode())
	return err
}

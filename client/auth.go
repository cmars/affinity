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

package client

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	. "github.com/juju/affinity"
)

const AuthDirName = "auth"
const AuthTokenSuffix = ".token"

var ErrAuthNotFound error = fmt.Errorf("Authorization not found")

// AuthTokenStore stores authentication tokens by their scheme and endpoint.
type AuthStore interface {
	// Get reads and decodes the authentication token from storage.
	Get(schemeId string, endpoint string) (*TokenInfo, error)
	// Set stores an authentication token.
	Set(token *TokenInfo, endpoint string) error
}

// FileAuthStore stores an affinity client's authentication credential
// in a directory structure with file naming convention.
type FileAuthStore struct {
	baseDir string
	authDir string
}

// NewFileAuthStore creates a new FileAuthStore at the given
// directory.
func NewFileAuthStore(baseDir string) (*FileAuthStore, error) {
	authDir := path.Join(baseDir, AuthDirName)
	err := os.MkdirAll(authDir, 0700)
	if err != nil {
		return nil, err
	}
	return &FileAuthStore{baseDir, authDir}, nil
}

func (s *FileAuthStore) tokenDirFile(schemeId string, endpoint string) (string, string) {
	schemeDir := path.Join(s.authDir, schemeId)
	return schemeDir, endpoint + AuthTokenSuffix
}

// Get retrieves a token for a scheme and endpoint.
func (s *FileAuthStore) Get(schemeId string, endpoint string) (*TokenInfo, error) {
	schemeDir, tokenFileName := s.tokenDirFile(schemeId, endpoint)
	tokenPath := path.Join(schemeDir, tokenFileName)
	if fi, err := os.Stat(tokenPath); err != nil {
		if os.IsNotExist(err) {
			err = ErrAuthNotFound
		}
		return nil, err
	} else if fi.Mode().IsDir() || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("Cannot retrieve %s token for endpoint %s: not a regular file", schemeId, endpoint)
	}
	authContents, err := ioutil.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = ErrAuthNotFound
		}
		return nil, err
	}
	auth := strings.TrimSpace(string(authContents))
	token, err := ParseTokenInfo(auth)
	if err != nil {
		return nil, err
	}
	if token.SchemeId != schemeId {
		return nil, fmt.Errorf("Token contents [%s] do not match requested scheme %s", token.SchemeId, schemeId)
	}
	return token, nil
}

// Set stores a token.
func (s *FileAuthStore) Set(token *TokenInfo, endpoint string) error {
	tokenDir, tokenName := s.tokenDirFile(token.SchemeId, endpoint)
	err := os.MkdirAll(tokenDir, 0700)
	if err != nil {
		return err
	}
	tokenPath := path.Join(tokenDir, tokenName)
	f, err := os.OpenFile(tokenPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, token.Serialize())
	return err
}

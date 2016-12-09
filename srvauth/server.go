/*
Copyright 2015 Rodrigo Rafael Monti Kochenburger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package srvauth

import (
	"log"
	"net/http"
	"net/url"

	"github.com/gostack/oauth22"
	"github.com/gostack/option"
	"github.com/husobee/vestigo"
	"github.com/satori/go.uuid"
)

type Persistence interface {
	LookupClient(ID uuid.UUID) (oauth22.Client, error)
}

// Strategy wraps the two optional interfaces that constitutes a OAuth2 strategies.
// Strategies should implement at least one of the interfaces.
type Strategy interface {
	ResponseType() (option.String, AuthorizationResponseType)
	GrantType() (option.String, TokenGrantType)
}

// AuthorizationResponseType is the interface that represents a valid OAuth2 response type, used by the authorization endpoint.
type AuthorizationResponseType interface {
	Confirm(ar oauth22.UserAuthorizationRequest, w http.ResponseWriter) error
	Authorize(ar oauth22.UserAuthorizationRequest) (*oauth22.UserAuthorization, error)
}

// TokenGrantType is the interface that represents a valid OAuth2 grant type, used by the token endpoint.
type TokenGrantType interface {
	IssueToken(c oauth22.Client, params url.Values) (*oauth22.AccessToken, error)
}

type Server struct {
	persistence   Persistence
	router        *vestigo.Router
	responseTypes map[string]AuthorizationResponseType
	grantTypes    map[string]TokenGrantType
}

func NewServer(p Persistence) *Server {
	srv := Server{
		persistence:   p,
		router:        vestigo.NewRouter(),
		responseTypes: make(map[string]AuthorizationResponseType),
		grantTypes:    make(map[string]TokenGrantType),
	}

	srv.router.Post("token", srv.tokenEndpointHandler)
	return &srv
}

func (s Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.router.ServeHTTP(w, req)
}

func (s *Server) RegisterStrategy(st Strategy) {
	if name, rt := st.ResponseType(); name.IsPresent() {
		if rt == nil {
			log.Fatal("%T ResponseType() returned name but nil AuthorizationResponseType", st)
		}
		s.responseTypes[name.Value()] = rt
	}

	if name, gt := st.GrantType(); name.IsPresent() {
		if gt == nil {
			log.Fatal("%T GrantType() returned name but nil TokenGrantType", st)
		}
		s.grantTypes[name.Value()] = gt
	}
}

func (s Server) authenticateClientRequest(req *http.Request) (*oauth22.Client, *OAuth2Error) {
	var textID, textSecret string

	if req.Header.Get("Authorization") != "" {
		var ok bool
		textID, textSecret, ok = req.BasicAuth()
		if !ok {
			return nil, ErrInvalidRequest
		}
	} else {
		textID = req.PostFormValue("client_id")
		textSecret = req.PostFormValue("client_secret")
	}

	if textID == "" || textSecret == "" {
		return nil, ErrInvalidRequest
	}

	var (
		id     uuid.UUID
		secret oauth22.Secret
	)

	if err := id.UnmarshalText([]byte(textID)); err != nil {
		return nil, ErrInvalidRequest
	}
	if err := secret.UnmarshalText([]byte(textSecret)); err != nil {
		return nil, ErrInvalidRequest
	}

	c, err := s.persistence.LookupClient(id)
	if err, ok := err.(*OAuth2Error); ok {
		return nil, err
	}
	if err != nil {
		return nil, ErrServerError
	}

	if !oauth22.SecureCompare(c.Secret, secret) {
		return nil, ErrInvalidClient
	}

	return &c, nil
}

func (s Server) tokenEndpointHandler(w http.ResponseWriter, req *http.Request) {

}

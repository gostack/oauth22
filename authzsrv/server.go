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

package authzsrv

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/satori/go.uuid"

	"github.com/gostack/oauth22"
	"github.com/gostack/oauth22/security"
)

// Server is the main class that implements the OAuth2 authorization server.
type Server struct {
	persistence   Persistence
	mux           *http.ServeMux
	responseTypes map[string]AuthorizationResponseType
	grantTypes    map[string]TokenGrantType
}

// NewServer instantiates a new Server configured for the provided Persistence.
func NewServer(p Persistence) *Server {
	srv := Server{
		persistence:   p,
		mux:           http.NewServeMux(),
		responseTypes: make(map[string]AuthorizationResponseType),
		grantTypes:    make(map[string]TokenGrantType),
	}

	srv.mux.HandleFunc("/token", srv.tokenEndpointHandler)
	return &srv
}

// ServeHTTP implements the net/http interface, allowing a Server to handle a HTTP route.
func (s Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mux.ServeHTTP(w, req)
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

func (s Server) authenticateClientRequest(req *http.Request) (*oauth22.Client, error) {
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
		return nil, ErrInvalidClient
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

	if !security.Compare(c.Secret, secret) {
		return nil, ErrInvalidClient
	}

	return c, nil
}

func (s Server) tokenEndpointHandler(w http.ResponseWriter, req *http.Request) {
	c, err := s.authenticateClientRequest(req)
	if err != nil {
		respondError(w, err)
		return
	}

	if err := req.ParseForm(); err != nil {
		respondError(w, ErrInvalidRequest)
		return
	}

	q := req.Form
	qGrantType := q.Get("grant_type")
	if qGrantType == "" {
		respondError(w, ErrUnsupportedGrantType)
		return
	}

	grantType, ok := s.grantTypes[qGrantType]
	if !ok {
		respondError(w, ErrUnsupportedGrantType)
	}

	accessToken, err := grantType.IssueToken(c, q)
	if err != nil {
		respondError(w, err)
		return
	}

	respondJSON(w, accessToken)
}

func respondJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}

func respondError(w http.ResponseWriter, err error) {
	if err, ok := err.(OAuth2Error); ok {
		w.WriteHeader(err.Code)
		respondJSON(w, err)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		respondJSON(w, ErrServerError)
	}
}

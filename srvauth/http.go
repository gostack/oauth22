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
	"github.com/gostack/oauth22"
	"net/http"
	"net/url"
)

// HTTPHandlers encapsulates the entire HTTP handling of the OAuth2 protocol.
// It delegates to underlying strategies
type HTTPHandlers struct {
	AuthorizationHandlers map[string]AuthorizationHandler
	TokenHandlers         map[string]TokenHandler
}

type AuthorizationHandler interface {
	Authorize(a *oauth22.UserAuthorizationRequest, w http.ResponseWriter)
}

type TokenHandler interface {
	IssueToken(c oauth22.Client, p url.Values) (oauth22.AccessToken, error)
}

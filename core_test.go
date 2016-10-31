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

package oauth22

import (
	"reflect"
	"testing"
)

func TestClientCredentials(t *testing.T) {
	c := Client{Name: "Test Client", RedirectURI: "https://example.test/oauth2/callback"}

	if err := c.generateCredentials(); err != nil {
		t.Error(err)
	}

	if c.ID == "" {
		t.Fatal("ID not properly initialized")
	}

	if c.Secret == "" {
		t.Fatal("Secret not properly initialized")
	}
}

func TestNewAccessToken(t *testing.T) {
	c := Client{Name: "Test Client", RedirectURI: "https://example.test/oauth2/callback"}

	at, err := NewAccessToken(c, []string{"basic"})
	if err != nil {
		t.Error(err)
	}

	if at.Token == "" {
		t.Fatal("token not properly generated")
	}

	if !reflect.DeepEqual([]string{"basic"}, at.Scopes) {
		t.Fatal("access token scopes not properly initialized")
	}
}

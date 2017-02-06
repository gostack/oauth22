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
	"bytes"
	"reflect"
	"testing"

	"github.com/gostack/oauth22/security"
)

func TestSecretMarshaling(t *testing.T) {
	b, err := security.Random(512)
	if err != nil {
		t.Fatal(err)
	}

	s := Secret(b)
	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	s = Secret{}
	err = s.UnmarshalText(text)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(b, s) {
		t.Error("marshaled and unmarshaled secret doesn't match")
	}
}

func TestClientCredentials(t *testing.T) {
	c := Client{Name: "Test Client", RedirectURI: "https://example.test/oauth2/callback"}

	if err := c.GenerateCredentials(); err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(c.ID, []byte("")) {
		t.Fatal("ID not properly initialized")
	}

	if reflect.DeepEqual(c.Secret, []byte("")) {
		t.Fatal("Secret not properly initialized")
	}
}

func TestNewAccessToken(t *testing.T) {
	c := Client{Name: "Test Client", RedirectURI: "https://example.test/oauth2/callback"}
	u := User{Username: "foobario", Password: []byte("password")}

	at, err := NewAccessToken(&c, &u, []string{"basic"})
	if err != nil {
		t.Error(err)
	}

	if reflect.DeepEqual(at.Token, []byte("")) {
		t.Fatal("token not properly generated")
	}

	if !reflect.DeepEqual([]string{"basic"}, at.Scopes) {
		t.Fatal("access token scopes not properly initialized")
	}
}

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
	"errors"

	"github.com/satori/go.uuid"
)

var ErrDoesntExist = errors.New("object doesn't exist")

// Persistence is the interface that applications will need to implement in order control
// persistence & lookup of OAuth2 related records.
type Persistence interface {
	LoaderClientFromID
	LoaderUserFromUsername
}

// LoaderClientFromID defines the interface for an object which knows how to handle a Client using
// it's ID.
type LoaderClientFromID interface {
	LoadClientFromID(id uuid.UUID) (*Client, error)
}

// LoaderUserFromUsername is the interface for objects that knows how to load a User from the
// provided username.
type LoaderUserFromUsername interface {
	LoadUserFromUsername(username string) (*User, error)
}

// InMemoryPersistence implements the Persistence interface using an in-memory persistence scheme.
// This is mainly for test purpose and should not be used in production.
type InMemoryPersistence struct {
	clients map[uuid.UUID]*Client
	users   map[string]*User
}

// NewInMemoryPersistence creates a new InMemoryPersistence and returns a pointer to it.
func NewInMemoryPersistence() *InMemoryPersistence {
	return &InMemoryPersistence{
		clients: make(map[uuid.UUID]*Client),
		users:   make(map[string]*User),
	}
}

// LoadClientFromID returns a client matching the provided id, otherwise returns an error.
func (p InMemoryPersistence) LoadClientFromID(id uuid.UUID) (*Client, error) {
	c, ok := p.clients[id]
	if !ok {
		return nil, nil
	}

	return c, nil
}

// LoadUserFromUsername returns a user matching the provided username, otherwise returns an error.
func (p InMemoryPersistence) LoadUserFromUsername(username string) (*User, error) {
	u, ok := p.users[username]
	if !ok {
		return nil, nil
	}

	return u, nil
}

// AUXILIARY METHODS BELOW, NOT PART OF THE INTERFACE

// RegisterClient persists a client
func (p *InMemoryPersistence) RegisterClient(c *Client) {
	p.clients[c.ID] = c
}

// RegisterUser perstists a user
func (p *InMemoryPersistence) RegisterUser(u *User) {
	p.users[u.Username] = u
}

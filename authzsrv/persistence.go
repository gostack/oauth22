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
	"github.com/gostack/oauth22"
	"github.com/satori/go.uuid"
)

// Persistence is the interface that applications will need to implement in order control
// persistence & lookup of OAuth2 related records.
type Persistence interface {
	// Returns an oauth22.Client or a ErrInvalidClient in case the client ID does not match any existing client.
	// Any other error will be treated as a Internal Server Error.
	LookupClient(id uuid.UUID) (*oauth22.Client, error)
}

// InMemoryPersistence implements the Persistence interface using an in-memory persistence scheme.
// This is mainly for test purpose and should not be used in production.
type InMemoryPersistence struct {
	clients map[uuid.UUID]*oauth22.Client
}

// NewInMemoryPersistence creates a new InMemoryPersistence and returns a pointer to it.
func NewInMemoryPersistence() *InMemoryPersistence {
	return &InMemoryPersistence{
		clients: make(map[uuid.UUID]*oauth22.Client),
	}
}

// LookupClient returns a client matching the provided id, otherwise returns an error.
func (p InMemoryPersistence) LookupClient(id uuid.UUID) (*oauth22.Client, error) {
	c, ok := p.clients[id]
	if !ok {
		return nil, ErrInvalidClient
	}

	return c, nil
}

// AUXILIARY METHODS BELOW, NOT PART OF THE INTERFACE

// RegisterClient persists the client
func (p *InMemoryPersistence) RegisterClient(c *oauth22.Client) {
	p.clients[c.ID] = c
}

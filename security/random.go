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

package security

import (
	"crypto/rand"
	"errors"
)

// Random generates a random sequence of N bytes
func Random(n uint16) ([]byte, error) {
	r := make([]byte, n)

	count, err := rand.Read(r)
	if err != nil {
		return nil, err
	}
	if n != uint16(count) {
		return nil, errors.New("unexpected length for generated string")
	}

	return r, nil
}

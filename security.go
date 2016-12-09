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
	"crypto/rand"
	"errors"
)

// secureBytes generates a random sequence of N bytes
func secureBytes(n uint16) ([]byte, error) {
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

// SecureCompare will compare two slice of bytes in constant time, ensuring no timing information
// is leaked in order to prevent timing attacks.
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

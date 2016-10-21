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
	"encoding/base64"
	"errors"
)

// secureToken generates a random sequence of N bytes and returns it encoded as base64
func secureToken(nBytes uint16) (string, error) {
	r := make([]byte, nBytes)

	n, err := rand.Read(r)
	if err != nil {
		return "", err
	}
	if nBytes != uint16(n) {
		return "", errors.New("unexpected length for generated string")
	}

	return base64.RawURLEncoding.EncodeToString(r), nil
}

// secureCompare will compare two slice of bytes in constant time, ensuring no timing information
// is leaked in order to prevent timing attacks.
func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

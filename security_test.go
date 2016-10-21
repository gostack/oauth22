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
	"testing"
)

func TestSecureToken(t *testing.T) {
	max := ^uint16(0)

	table := []struct {
		nBytes uint16
		length uint32
	}{
		{nBytes: 32, length: 43},
		{nBytes: 64, length: 86},
		{nBytes: 128, length: 171},
		{nBytes: 256, length: 342},
		{nBytes: 1024, length: 1366},
		{nBytes: 4096, length: 5462},
		{nBytes: max, length: 87380},
	}

	for i, e := range table {
		tk, err := secureToken(e.nBytes)
		if err != nil {
			t.Error(err)
		}
		if uint32(len(tk)) != e.length {
			t.Errorf("entry #%d: expected token with %d bytes to be encoded in %d characters but was %d", i, e.nBytes, e.length, len(tk))
		}
	}
}

func TestSecureCompare(t *testing.T) {
	table := []struct {
		A, B   string
		Result bool
	}{
		{"CZEXIa-mVtAvzrJV8-q-MGiynZf476lMo9Ba1Be4L3Y", "CZEXIa-mVtAvzrJV8-q-MGiynZf476lMo9Ba1Be4L3Y", true},
		{"J1ye8B7nGPfImUiXS2xK9EQZT-3NuAG-Kt7qg51sAhU", "J1ye8B7nGPfImUiXS2xK9EQZT-3NuAG-Kt7qg51sAhU", true},
		{"CZEXIa-mVtAvzrJV8-q-MGiynZf476lMo9Ba1Be4L3Y", "J1ye8B7nGPfImUiXS2xK9EQZT-3NuAG-Kt7qg51sAhU", false},
	}

	for i, e := range table {
		var r string
		if e.Result {
			r = "match"
		} else {
			r = "not match"
		}

		if secureCompare([]byte(e.A), []byte(e.B)) != e.Result {
			t.Errorf("expected entry #%d with %s and %s to %s", i, e.A, e.B, r)
		}
	}
}

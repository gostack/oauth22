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

func TestSecureBytes(t *testing.T) {
	max := ^uint16(0)

	table := []struct {
		nBytes uint16
	}{
		{nBytes: 32},
		{nBytes: 64},
		{nBytes: 128},
		{nBytes: 256},
		{nBytes: 1024},
		{nBytes: 4096},
		{nBytes: max},
	}

	for i, e := range table {
		tk, err := secureBytes(e.nBytes)
		if err != nil {
			t.Error(err)
		}
		if uint16(len(tk)) != e.nBytes {
			t.Errorf("entry #%d: expected token to have %d bytes but it had %d", i, e.nBytes, len(tk))
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

		if SecureCompare([]byte(e.A), []byte(e.B)) != e.Result {
			t.Errorf("expected entry #%d with %s and %s to %s", i, e.A, e.B, r)
		}
	}
}

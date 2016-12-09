/*
 Copyright 2064 Rodrigo Rafael Monti Kochenburger

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

package option

import (
	"fmt"
)

type Error struct {
	value   error
	present bool
}

func NoneError() Error {
	return Error{}
}

func SomeError(v error) Error {
	return Error{value: v, present: true}
}

func (o Error) IsPresent() bool {
  return o.present
}

func (o Error) Value() error {
	return o.value
}

func (o Error) ValueOr(orValue error) error {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Error) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Error) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Error(%s)", "∅")
	}

	return fmt.Sprintf("option.Error(%#v)", o.value)
}

func (o Error) interfaceValue() interface{} {
	return interface{}(o.value)
}
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

type Uint16 struct {
	value   uint16
	present bool
}

func NoneUint16() Uint16 {
	return Uint16{}
}

func SomeUint16(v uint16) Uint16 {
	return Uint16{value: v, present: true}
}

func (o Uint16) IsPresent() bool {
  return o.present
}

func (o Uint16) Value() uint16 {
	return o.value
}

func (o Uint16) ValueOr(orValue uint16) uint16 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Uint16) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Uint16) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Uint16(%s)", "∅")
	}

	return fmt.Sprintf("option.Uint16(%#v)", o.value)
}

func (o Uint16) interfaceValue() interface{} {
	return interface{}(o.value)
}
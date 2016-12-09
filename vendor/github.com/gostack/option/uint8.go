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

type Uint8 struct {
	value   uint8
	present bool
}

func NoneUint8() Uint8 {
	return Uint8{}
}

func SomeUint8(v uint8) Uint8 {
	return Uint8{value: v, present: true}
}

func (o Uint8) IsPresent() bool {
  return o.present
}

func (o Uint8) Value() uint8 {
	return o.value
}

func (o Uint8) ValueOr(orValue uint8) uint8 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Uint8) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Uint8) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Uint8(%s)", "∅")
	}

	return fmt.Sprintf("option.Uint8(%#v)", o.value)
}

func (o Uint8) interfaceValue() interface{} {
	return interface{}(o.value)
}
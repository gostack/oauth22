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

type Uint32 struct {
	value   uint32
	present bool
}

func NoneUint32() Uint32 {
	return Uint32{}
}

func SomeUint32(v uint32) Uint32 {
	return Uint32{value: v, present: true}
}

func (o Uint32) IsPresent() bool {
  return o.present
}

func (o Uint32) Value() uint32 {
	return o.value
}

func (o Uint32) ValueOr(orValue uint32) uint32 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Uint32) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Uint32) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Uint32(%s)", "∅")
	}

	return fmt.Sprintf("option.Uint32(%#v)", o.value)
}

func (o Uint32) interfaceValue() interface{} {
	return interface{}(o.value)
}
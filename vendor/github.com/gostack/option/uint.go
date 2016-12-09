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

type Uint struct {
	value   uint
	present bool
}

func NoneUint() Uint {
	return Uint{}
}

func SomeUint(v uint) Uint {
	return Uint{value: v, present: true}
}

func (o Uint) IsPresent() bool {
  return o.present
}

func (o Uint) Value() uint {
	return o.value
}

func (o Uint) ValueOr(orValue uint) uint {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Uint) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Uint) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Uint(%s)", "∅")
	}

	return fmt.Sprintf("option.Uint(%#v)", o.value)
}

func (o Uint) interfaceValue() interface{} {
	return interface{}(o.value)
}
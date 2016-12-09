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

type Uint64 struct {
	value   uint64
	present bool
}

func NoneUint64() Uint64 {
	return Uint64{}
}

func SomeUint64(v uint64) Uint64 {
	return Uint64{value: v, present: true}
}

func (o Uint64) IsPresent() bool {
  return o.present
}

func (o Uint64) Value() uint64 {
	return o.value
}

func (o Uint64) ValueOr(orValue uint64) uint64 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Uint64) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Uint64) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Uint64(%s)", "∅")
	}

	return fmt.Sprintf("option.Uint64(%#v)", o.value)
}

func (o Uint64) interfaceValue() interface{} {
	return interface{}(o.value)
}
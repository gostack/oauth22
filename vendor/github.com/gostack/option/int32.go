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

type Int32 struct {
	value   int32
	present bool
}

func NoneInt32() Int32 {
	return Int32{}
}

func SomeInt32(v int32) Int32 {
	return Int32{value: v, present: true}
}

func (o Int32) IsPresent() bool {
  return o.present
}

func (o Int32) Value() int32 {
	return o.value
}

func (o Int32) ValueOr(orValue int32) int32 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Int32) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Int32) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Int32(%s)", "∅")
	}

	return fmt.Sprintf("option.Int32(%#v)", o.value)
}

func (o Int32) interfaceValue() interface{} {
	return interface{}(o.value)
}
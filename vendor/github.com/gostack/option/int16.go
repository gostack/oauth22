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

type Int16 struct {
	value   int16
	present bool
}

func NoneInt16() Int16 {
	return Int16{}
}

func SomeInt16(v int16) Int16 {
	return Int16{value: v, present: true}
}

func (o Int16) IsPresent() bool {
  return o.present
}

func (o Int16) Value() int16 {
	return o.value
}

func (o Int16) ValueOr(orValue int16) int16 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Int16) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Int16) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Int16(%s)", "∅")
	}

	return fmt.Sprintf("option.Int16(%#v)", o.value)
}

func (o Int16) interfaceValue() interface{} {
	return interface{}(o.value)
}
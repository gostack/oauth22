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

type Int struct {
	value   int
	present bool
}

func NoneInt() Int {
	return Int{}
}

func SomeInt(v int) Int {
	return Int{value: v, present: true}
}

func (o Int) IsPresent() bool {
  return o.present
}

func (o Int) Value() int {
	return o.value
}

func (o Int) ValueOr(orValue int) int {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Int) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Int) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Int(%s)", "∅")
	}

	return fmt.Sprintf("option.Int(%#v)", o.value)
}

func (o Int) interfaceValue() interface{} {
	return interface{}(o.value)
}
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

type Bool struct {
	value   bool
	present bool
}

func NoneBool() Bool {
	return Bool{}
}

func SomeBool(v bool) Bool {
	return Bool{value: v, present: true}
}

func (o Bool) IsPresent() bool {
  return o.present
}

func (o Bool) Value() bool {
	return o.value
}

func (o Bool) ValueOr(orValue bool) bool {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Bool) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Bool) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Bool(%s)", "∅")
	}

	return fmt.Sprintf("option.Bool(%#v)", o.value)
}

func (o Bool) interfaceValue() interface{} {
	return interface{}(o.value)
}
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

type Float32 struct {
	value   float32
	present bool
}

func NoneFloat32() Float32 {
	return Float32{}
}

func SomeFloat32(v float32) Float32 {
	return Float32{value: v, present: true}
}

func (o Float32) IsPresent() bool {
  return o.present
}

func (o Float32) Value() float32 {
	return o.value
}

func (o Float32) ValueOr(orValue float32) float32 {
	if !o.present {
		return orValue
	}
	return o.value
}

func (o Float32) String() string {
	if !o.present {
		return "∅"
	}

	return fmt.Sprintf("%v", o.value)
}

func (o Float32) GoString() string {
	if !o.present {
		return fmt.Sprintf("option.Float32(%s)", "∅")
	}

	return fmt.Sprintf("option.Float32(%#v)", o.value)
}

func (o Float32) interfaceValue() interface{} {
	return interface{}(o.value)
}
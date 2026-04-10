// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package mapstr

import (
	structform "github.com/elastic/go-structform"
	"github.com/elastic/go-structform/gotype"
)

// Fold implements go-structform's gotype.Folder interface, letting
// go-structform serialize M without the reflect.Convert overhead it
// normally incurs for named map types.
func (m M) Fold(v structform.ExtVisitor) error {
	if err := v.OnObjectStart(len(m), structform.AnyType); err != nil {
		return err
	}
	for k, val := range m {
		if err := v.OnKey(k); err != nil {
			return err
		}
		switch x := val.(type) {
		case string:
			if err := v.OnString(x); err != nil {
				return err
			}
		case M:
			if err := x.Fold(v); err != nil {
				return err
			}
		case int:
			if err := v.OnInt(x); err != nil {
				return err
			}
		case map[string]interface{}:
			if err := M(x).Fold(v); err != nil {
				return err
			}
		default:
			if err := gotype.Fold(val, v); err != nil {
				return err
			}
		}
	}
	return v.OnObjectFinished()
}

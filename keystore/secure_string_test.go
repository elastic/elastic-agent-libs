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

package keystore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var secret = []byte("mysecret")

func TestGet(t *testing.T) {
	s := NewSecureString(secret)
	v, err := s.Get()
	assert.Equal(t, secret, v)
	assert.NoError(t, err)
}

func TestStringMarshalingS(t *testing.T) {
	s := NewSecureString(secret)
	v := fmt.Sprintf("%s", s) //nolint: gosimple // the goal of the test is to check if the string is not printed

	assert.Equal(t, v, "<SecureString>")
}

func TestStringMarshalingF(t *testing.T) {
	s := NewSecureString(secret)
	v := fmt.Sprintf("%v", s)

	assert.Equal(t, v, "<SecureString>")
}

func TestStringGoStringerMarshaling(t *testing.T) {
	s := NewSecureString(secret)
	v := fmt.Sprintf("%#v", s)

	assert.Equal(t, v, "<SecureString>")
}

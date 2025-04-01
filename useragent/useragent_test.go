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

package useragent

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	v         = "9.9.9"
	commit    = "1234abcd"
	buildTime = "20001212"
)

func TestUserAgent(t *testing.T) {
	ua := UserAgent("FakeBeat", v, commit, buildTime)
	assert.Regexp(t, regexp.MustCompile(`^Elastic-FakeBeat`), ua)

	ua2 := UserAgent("FakeBeat", v, commit, buildTime, "integration_name/1.2.3")
	assert.Regexp(t, regexp.MustCompile(`\(integration_name\/1\.2\.3;`), ua2)
}

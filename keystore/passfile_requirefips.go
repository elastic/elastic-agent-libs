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

//go:build requirefips

package keystore

import (
	"fmt"
	"io"
	"os"
)

// loadPassfile will read the path and return a SecureString.
//
// When built with the requirefips tag, a non-empty path is expected.
// The passfile must contain a password with at least 112 bits.
func loadPassfile(path string) (*SecureString, error) {
	if path == "" {
		return nil, fmt.Errorf("no passfile_path specified")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open %q: %w", path, err)
	}
	defer f.Close()
	p, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("unable to read %q: %w", path, err)
	}
	if len(p) == 0 {
		return nil, fmt.Errorf("passfile %q contains no bytes", path)
	}
	if len(p) < 14 { // 112 bits
		return nil, fmt.Errorf("passfile %q length %d is under FIPS required length")
	}
	return NewSecureString(p), nil
}

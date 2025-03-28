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

package tlscommon

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFIPSCertifacteAndKeys tests that encrypted private keys fail in FIPS mode
func TestFIPSCertificateAndKeys(t *testing.T) {
	if checkGODEBUG() {
		t.Skip("GODEBUG=fips140=only detected, avoiding panics")
	}
	t.Run("embed encrypted PKCS#1 key", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		password := "abcd1234"
		key, cert := makeKeyCertPair(t, blockTypePKCS1Encrypted, password)
		cfg, err := load(`enabled: true`)
		require.NoError(t, err)
		cfg.Certificate.Certificate = cert
		cfg.Certificate.Key = key
		cfg.Certificate.Passphrase = password

		_, err = LoadTLSConfig(cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnsupported, err)
	})

	t.Run("embed encrypted PKCS#8 key", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		password := "abcd1234"
		key, cert := makeKeyCertPair(t, blockTypePKCS8Encrypted, password)
		cfg, err := load(`enabled: true`)
		require.NoError(t, err)
		cfg.Certificate.Certificate = cert
		cfg.Certificate.Key = key
		cfg.Certificate.Passphrase = password

		_, err = LoadTLSConfig(cfg)
		assert.ErrorIs(t, err, errors.ErrUnsupported)
	})
}

// checkGODEBUG returns true if the GODEBUG env var contains fips140=only
func checkGODEBUG() bool {
	// NOTE: This only checks env var; at the time of writing fips140 can only be set via env
	// other GODEBUG settings can be set via embedded comments or in go.mod, we may need to account for this in the future.
	ss := strings.Split(os.Getenv("GODEBUG"), ",")
	for _, s := range ss {
		if s == "fips140=only" {
			return true
		}
	}
	return false
}

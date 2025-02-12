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
	"github.com/elastic/elastic-agent-libs/config"
)

// NopKeystore is used in FIPS mode to a beats keystore.
type NopKeystore struct{}

// NewFileKeystoreWithPasswordAndStrictPerms returns a NopKeystore.
//
// It is using an exising, exported function call name so callers do not need to change the function call, just the build tag.
func NewFileKeystoreWithPasswordAndStrictPerms(keystoreFile string, password *SecureString, strictPerms bool) (Keystore, error) {
	return &NopKeystore{}, nil
}

// Retrieve returns ErrKeyDoesntExists
func (*NopKeystore) Retrieve(key string) (*SecureString, error) {
	return nil, ErrKeyDoesntExists
}

// Store returns ErrKeystoreDisabled
func (*NopKeystore) Store(key string, value []byte) error {
	return nil, ErrKeystoreDisabled
}

// Delete is a nop that returns nil
func (*NopKeystore) Delete(key string) error {
	return nil
}

// Save returns ErrKeystoreDisabled
func (*NopKeystore) Save() error {
	return ErrKeystoreDisabled
}

// List is a nop that returns a 0 length list of strings
func (*NopKeystore) List() ([]string, error) {
	return []string{}, nil
}

// GetConfig returns is a nop that returns a new config.C
func (*NopKeystore) GetConfig() (*config.C, error) {
	return config.NewConfig(), nil
}

// Create returns ErrKeystoreDisabled
func (*NopKeystore) Create(override bool) error {
	return ErrKeystoreDisabled
}

// IsPersisted always retuns false
func (*NopKeystore) IsPersisted() bool {
	return false
}

// Package is a nop that always returns nil
func (*NopKeystore) Package() ([]byte, error) {
	return nil, nil
}

// ConfiguredPath retuns an empty string
func (*NopKeystore) ConfiguredPath() string {
	return ""
}

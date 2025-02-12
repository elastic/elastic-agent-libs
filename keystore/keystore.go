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
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/parse"
)

var (
	// ErrAlreadyExists is returned when the file already exist at the location.
	ErrAlreadyExists = errors.New("cannot create a new keystore a valid keystore already exist at the location")

	// ErrKeyDoesntExists is returned when the key doesn't exist in the store
	ErrKeyDoesntExists = errors.New("cannot retrieve the key")

	// ErrNotWritable is returned when the keystore is not writable
	ErrNotWritable = errors.New("the configured keystore is not writable")

	// ErrNotWritable is returned when the keystore is not writable
	ErrNotListing = errors.New("the configured keystore is not listing")

	// ErrKeystoreDisabled is returned on create, save, and store operations if built with the requirefips flag
	ErrKeystoreDisabled = fmt.Errorf("keystore disabled in FIPS mode: %w", errors.ErrUnsupported)
)

const (
	filePermission = 0600

	// Encryption Related constants
	iVLength        = 12
	saltLength      = 64
	iterationsCount = 10000
	keyLength       = 32
)

// Version of the keystore format, will be added at the beginning of the file.
var version = []byte("v1")

// Keystore implement a way to securely saves and retrieves secrets to be used in the configuration
// Currently all credentials are loaded upfront and are not lazy retrieved, we will eventually move
// to that concept, so we can deal with tokens that has a limited duration or can be revoked by a
// remote keystore.
type Keystore interface {
	// Retrieve returns a SecureString instance of the searched key or an error.
	Retrieve(key string) (*SecureString, error)

	// GetConfig returns the key value pair in the config format to be merged with other configuration.
	GetConfig() (*config.C, error)

	// IsPersisted check if the current keystore is persisted.
	IsPersisted() bool
}

type WritableKeystore interface {
	// Store add keys to the keystore, wont be persisted until we save.
	Store(key string, secret []byte) error

	// Delete removes a specific key from the keystore.
	Delete(key string) error

	// Create Allow to create an empty keystore.
	Create(override bool) error

	// Save persist the changes to the keystore.
	Save() error
}

type ListingKeystore interface {
	// List returns the list of keys in the keystore, return an empty list if none is found.
	List() ([]string, error)
}

// Packager defines a keystore that we can read the raw bytes and be packaged in an artifact.
type Packager interface {
	Package() ([]byte, error)
	ConfiguredPath() string
}

// Use parse.NoopConfig to disable interpreting all parser characters when loading secrets.
var parseConfig = parse.NoopConfig

// ResolverWrap wrap a config resolver around an existing keystore.
func ResolverWrap(keystore Keystore) func(string) (string, parse.Config, error) {
	return func(keyName string) (string, parse.Config, error) {
		key, err := keystore.Retrieve(keyName)

		if err != nil {
			// If we cannot find the key, its a non fatal error
			// and we pass to other resolver.
			if errors.Is(err, ErrKeyDoesntExists) {
				return "", parseConfig, ucfg.ErrMissing
			}
			return "", parseConfig, err
		}

		v, err := key.Get()
		if err != nil {
			return "", parseConfig, err
		}

		return string(v), parseConfig, nil
	}
}

// AsWritableKeystore casts a keystore to WritableKeystore, returning an ErrNotWritable error if the given keystore does not implement
// WritableKeystore interface
func AsWritableKeystore(store Keystore) (WritableKeystore, error) {
	w, ok := store.(WritableKeystore)
	if !ok {
		return nil, ErrNotWritable
	}
	return w, nil
}

// AsListingKeystore casts a keystore to ListingKeystore, returning an ErrNotListing error if the given keystore does not implement
// ListingKeystore interface
func AsListingKeystore(store Keystore) (ListingKeystore, error) {
	w, ok := store.(ListingKeystore)
	if !ok {
		return nil, ErrNotListing
	}
	return w, nil
}

// Factory Create the right keystore with the configured options.
func Factory(c *config.C, defaultPath string, strictPerms bool) (Keystore, error) {
	cfg := defaultConfig()

	if c == nil {
		c = config.NewConfig()
	}
	err := c.Unpack(&cfg)

	if err != nil {
		return nil, fmt.Errorf("could not read keystore configuration, err: %w", err)
	}

	if cfg.Path == "" {
		cfg.Path = defaultPath
	}

	keystore, err := NewFileKeystoreWithStrictPerms(cfg.Path, strictPerms)
	return keystore, err
}

// NewFileKeystore returns an new File based keystore or an error, currently users cannot set their
// own password on the keystore, the default password will be an empty string. When the keystore
// is initialized the secrets are automatically loaded into memory.
func NewFileKeystore(keystoreFile string) (Keystore, error) {
	return NewFileKeystoreWithStrictPerms(keystoreFile, false)
}

// NewFileKeystore returns an new File based keystore or an error, currently users cannot set their
// own password on the keystore, the default password will be an empty string. When the keystore
// is initialized the secrets are automatically loaded into memory.
func NewFileKeystoreWithStrictPerms(keystoreFile string, strictPerms bool) (Keystore, error) {
	return NewFileKeystoreWithPasswordAndStrictPerms(keystoreFile, NewSecureString([]byte("")), strictPerms)
}

// NewFileKeystoreWithPassword return a new File based keystore or an error, allow to define what
// password to use to create the keystore.
func NewFileKeystoreWithPassword(keystoreFile string, password *SecureString) (Keystore, error) {
	return NewFileKeystoreWithPasswordAndStrictPerms(keystoreFile, password, false)
}

// randomBytes return a slice of random bytes of the defined length
func randomBytes(length int) ([]byte, error) {
	r := make([]byte, length)
	_, err := rand.Read(r)

	if err != nil {
		return nil, err
	}

	return r, nil
}

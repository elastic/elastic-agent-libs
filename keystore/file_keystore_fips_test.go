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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/go-ucfg"
)

func Test_NopKeystore_Retrieve(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)

	_, err = keyStore.Retrieve("key")
	require.ErrorIs(t, err, ErrKeyDoesntExists)
}

func Test_NopKeystore_GetConfig(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)

	cfg, err := keyStore.GetConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Empty(t, cfg.FlattenedKeys(), "Unexpected key found in NopKeystore config")
}

func Test_NopKeystore_IsPersisted(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)

	require.False(t, keyStore.IsPersisted(), "expected NopKeystore to indicate no persisted values")
}

func Test_NopKeystore_Store(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)
	writable, err := AsWritableKeystore(keyStore)
	require.NoError(t, err)

	err = writable.Store("key", []byte("value"))
	require.ErrorIs(t, err, ErrKeystoreDisabled)
}

func Test_NopKeystore_Delete(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)
	writable, err := AsWritableKeystore(keyStore)
	require.NoError(t, err)

	require.NoError(t, writable.Delete("key"))
}

func Test_NopKeystore_Create(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)
	writable, err := AsWritableKeystore(keyStore)
	require.NoError(t, err)

	err = writable.Create(true)
	require.ErrorIs(t, err, ErrKeystoreDisabled)
}

func Test_NopKeystore_Save(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)
	writable, err := AsWritableKeystore(keyStore)
	require.NoError(t, err)

	err = writable.Save()
	require.ErrorIs(t, err, ErrKeystoreDisabled)
}

func Test_NopKeystore_List(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)
	listing, err := AsListingKeystore(keyStore)
	require.NoError(t, err)

	list, err := listing.List()
	require.NoError(t, err)
	require.EqualValues(t, []string{}, list, "unexpected key in keystore")
}

func Test_NopKeystore_Package(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)

	packager, ok := keyStore.(Packager)
	require.True(t, ok, "Expected to be able to cast NopKeystore as Packager")

	p, err := packager.Package()
	require.NoError(t, err)
	require.Nil(t, p)
}

func Test_NopKeystore_ConfiguredPath(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)

	packager, ok := keyStore.(Packager)
	require.True(t, ok, "Expected to be able to cast NopKeystore as Packager")

	require.Equal(t, "", packager.ConfiguredPath())
}

func Test_NopKeystore_ResolverWrap(t *testing.T) {
	keyStore, err := NewFileKeystoreWithPasswordAndStrictPerms("a/path", nil, false)
	require.NoError(t, err)

	resolver := ResolverWrap(keyStore)
	_, _, err = resolver("key")
	require.ErrorIs(t, err, ucfg.ErrMissing)
}

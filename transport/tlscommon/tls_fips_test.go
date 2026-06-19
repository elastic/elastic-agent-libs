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
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp/logptest"
)

// TestFIPSVerifyConnectionRejectsBadCerts verifies that all client verification
// modes reject a server certificate with a non-compliant key (1024-bit RSA,
// below the FIPS 140-3 minimum of 2048 bits).
func TestFIPSVerifyConnectionRejectsBadCerts(t *testing.T) {
	caCert, err := os.ReadFile(filepath.Join("testdata", "ca.crt"))
	require.NoError(t, err)
	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join("testdata", "fips_invalid.crt"),
		filepath.Join("testdata", "fips_invalid.key"),
	)
	require.NoError(t, err)

	serverURL := startTestServer(t, "localhost:0", []tls.Certificate{serverCert})

	for _, mode := range []string{"full", "certificate", "strict", "none"} {
		t.Run("verification_mode="+mode, func(t *testing.T) {
			cfg, err := load(`enabled: true`)
			require.NoError(t, err)
			cfg.VerificationMode = tlsVerificationModes[mode]
			cfg.CAs = []string{string(caCert)}

			tlsCfg, err := LoadTLSConfig(cfg, logptest.NewTestingLogger(t, ""))
			require.NoError(t, err)

			err = dialTestServer(serverURL, tlsCfg)
			require.Error(t, err, "expected FIPS rejection for mode %q", mode)
			assert.Contains(t, err.Error(), "not allowed by FIPS 140-3", "expected FIPS error for mode %q, got: %v", mode, err)
		})
	}
}

// TestFIPSVerifyConnectionAllowsGoodCerts tests that compliant certificates
// (2048-bit RSA, testdata/fips_valid.crt) are accepted in all verification modes.
func TestFIPSVerifyConnectionAllowsGoodCerts(t *testing.T) {
	caCert, err := os.ReadFile(filepath.Join("testdata", "ca.crt"))
	require.NoError(t, err)
	// fips_valid.crt is a 2048-bit RSA cert signed by the testdata CA — FIPS 140-3 compliant.
	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join("testdata", "fips_valid.crt"),
		filepath.Join("testdata", "fips_valid.key"),
	)
	require.NoError(t, err)

	serverURL := startTestServer(t, "localhost:0", []tls.Certificate{serverCert})

	for _, mode := range []string{"full", "certificate", "none"} {
		t.Run("verification_mode="+mode, func(t *testing.T) {
			cfg, err := load(`enabled: true`)
			require.NoError(t, err)
			cfg.VerificationMode = tlsVerificationModes[mode]
			cfg.CAs = []string{string(caCert)}

			tlsCfg, err := LoadTLSConfig(cfg, logptest.NewTestingLogger(t, ""))
			require.NoError(t, err)

			err = dialTestServer(serverURL, tlsCfg)
			require.NoError(t, err, "FIPS-compliant cert should be accepted for mode %q", mode)
		})
	}
}

// dialTestServer makes a single HTTPS GET to serverURL using the given TLSConfig
// and returns any TLS-level error (connection or handshake).
func dialTestServer(serverURL url.URL, cfg *TLSConfig) error {
	tlsNativeCfg := cfg.BuildModuleClientConfig(serverURL.Hostname())
	transport := &http.Transport{TLSClientConfig: tlsNativeCfg}
	transport.ForceAttemptHTTP2 = false
	client := &http.Client{Transport: transport}
	resp, err := client.Get(serverURL.String()) //nolint:noctx // testing
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestFIPSCertifacteAndKeys tests that encrypted private keys fail in FIPS mode
func TestFIPSCertificateAndKeys(t *testing.T) {
	t.Run("embed encrypted PKCS#1 key", func(t *testing.T) {
		password := "abcd1234"

		keyFile, err := os.Open(filepath.Join("testdata", "key.pkcs1encrypted.pem"))
		require.NoError(t, err)
		defer keyFile.Close()
		rawKey, err := io.ReadAll(keyFile)
		require.NoError(t, err)

		certFile, err := os.Open(filepath.Join("testdata", "cert.pkcs1encrypted.pem"))
		require.NoError(t, err)
		defer certFile.Close()
		rawCert, err := io.ReadAll(certFile)
		require.NoError(t, err)

		cfg, err := load(`enabled: true`)
		require.NoError(t, err)
		cfg.Certificate.Certificate = string(rawCert)
		cfg.Certificate.Key = string(rawKey)
		cfg.Certificate.Passphrase = password

		_, err = LoadTLSConfig(cfg, logptest.NewTestingLogger(t, ""))
		require.Error(t, err)
		assert.ErrorIs(t, err, errors.ErrUnsupported, err)
	})

	t.Run("embed encrypted PKCS#8 key", func(t *testing.T) {
		// Create a dummy configuration and append the CA after.
		password := "abcdefg1234567"
		key, cert := makeKeyCertPair(t, blockTypePKCS8Encrypted, password)
		cfg, err := load(`enabled: true`)
		require.NoError(t, err)
		cfg.Certificate.Certificate = cert
		cfg.Certificate.Key = key
		cfg.Certificate.Passphrase = password

		_, err = LoadTLSConfig(cfg, logptest.NewTestingLogger(t, ""))
		assert.ErrorIs(t, err, errors.ErrUnsupported)
	})
}

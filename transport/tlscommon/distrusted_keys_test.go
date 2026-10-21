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

package tlscommon

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/transport/tlscommontest"
)

// distrustedChainCerts is a root -> intermediate -> leaf chain where the
// intermediate stands in for a compromised CA.
type distrustedChainCerts struct {
	root         *x509.Certificate
	intermediate *x509.Certificate
	leaf         *x509.Certificate
	// serverCert is the leaf plus the intermediate, as a server would present it.
	serverCert tls.Certificate
}

// genChain generates a root CA, an intermediate CA signed by it and a leaf
// for "localhost" signed by the intermediate.
func genChain(t *testing.T) distrustedChainCerts {
	t.Helper()

	root, err := tlscommontest.GenCA()
	require.NoError(t, err, "generating root CA")

	intermediate, err := tlscommontest.GenSignedCert(root,
		x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign, true,
		"Compromised Intermediate CA", nil, nil, false)
	require.NoError(t, err, "generating intermediate CA")

	leaf, err := tlscommontest.GenSignedCert(intermediate,
		x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, false,
		"localhost", []string{"localhost"}, []net.IP{{127, 0, 0, 1}}, false)
	require.NoError(t, err, "generating leaf certificate")

	return distrustedChainCerts{
		root:         root.Leaf,
		intermediate: intermediate.Leaf,
		leaf:         leaf.Leaf,
		serverCert: tls.Certificate{
			Certificate: [][]byte{leaf.Leaf.Raw, intermediate.Leaf.Raw},
			PrivateKey:  leaf.PrivateKey,
			Leaf:        leaf.Leaf,
		},
	}
}

// handshake runs a TLS handshake between a client using clientCfg and a
// server presenting serverCert, and returns the error seen by the client.
func handshake(t *testing.T, serverCert tls.Certificate, clientCfg *tls.Config) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// A loopback listener is used rather than net.Pipe: pipes are unbuffered,
	// so the alert sent by a rejecting client and the server writes would
	// block each other.
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err, "listening on loopback")
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		// The error is reported by the client side, which is what the test asserts on.
		_ = tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		}).HandshakeContext(ctx)
	}()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	require.NoError(t, err, "dialing test server")
	defer conn.Close()

	return tls.Client(conn, clientCfg).HandshakeContext(ctx)
}

// distrustForTest adds the public key of cert to the distrusted list for the
// duration of the test.
func distrustForTest(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	hash := hex.EncodeToString(sum[:])
	distrustedSPKISHA256[hash] = "Test CA"
	t.Cleanup(func() { delete(distrustedSPKISHA256, hash) })
}

func TestDistrustedKeyListIsWellFormed(t *testing.T) {
	// The list is hand copied from the published list of impacted
	// intermediates and must match the one shipped in Go 1.26.10 / 1.27.3.
	assert.Len(t, distrustedSPKISHA256, 8, "expected the eight eMudhra intermediates")

	sha256Hex := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for hash, name := range distrustedSPKISHA256 {
		assert.Regexp(t, sha256Hex, hash, "hash for %q must be lowercase hex SHA-256", name)
		assert.NotEmpty(t, name, "every distrusted key needs a name for error messages")
	}
}

func TestFilterDistrustedChains(t *testing.T) {
	certs := genChain(t)
	distrustForTest(t, certs.intermediate)

	clean, err := tlscommontest.GenCA()
	require.NoError(t, err, "generating clean CA")

	bad := []*x509.Certificate{certs.leaf, certs.intermediate, certs.root}
	good := []*x509.Certificate{certs.leaf, clean.Leaf}

	tests := map[string]struct {
		chains    [][]*x509.Certificate
		want      [][]*x509.Certificate
		wantError bool
	}{
		"nil input is returned unchanged": {
			chains: nil,
			want:   nil,
		},
		"empty input is returned unchanged": {
			chains: [][]*x509.Certificate{},
			want:   [][]*x509.Certificate{},
		},
		"clean chain is kept": {
			chains: [][]*x509.Certificate{good},
			want:   [][]*x509.Certificate{good},
		},
		"distrusted chain is rejected": {
			chains:    [][]*x509.Certificate{bad},
			wantError: true,
		},
		"all chains distrusted is rejected": {
			chains:    [][]*x509.Certificate{bad, bad},
			wantError: true,
		},
		"one clean chain is enough": {
			chains: [][]*x509.Certificate{bad, good},
			want:   [][]*x509.Certificate{good},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := filterDistrustedChains(tc.chains)
			if tc.wantError {
				require.ErrorIs(t, err, ErrDistrustedKey, "chains through a distrusted key must be rejected")
				assert.Contains(t, err.Error(), "Test CA", "error should name the distrusted CA")
				assert.Nil(t, got, "no chains should be returned on error")
				return
			}
			require.NoError(t, err, "chains without distrusted keys must be accepted")
			assert.Equal(t, tc.want, got, "only chains free of distrusted keys should remain")
		})
	}
}

// TestVerifyConnectionDistrustedIntermediate checks that every client
// verification mode that builds a chain rejects a server certificate issued by
// a distrusted intermediate, even though the root is trusted, and accepts the
// same chain once the intermediate is not distrusted.
func TestVerifyConnectionDistrustedIntermediate(t *testing.T) {
	logger := logptest.NewTestingLogger(t, "")

	peerCerts := func(c distrustedChainCerts) []*x509.Certificate {
		return []*x509.Certificate{c.leaf, c.intermediate}
	}

	modes := map[string]struct {
		mode    TLSVerificationMode
		dynamic bool
	}{
		"full":           {mode: VerifyFull},
		"certificate":    {mode: VerifyCertificate},
		"strict dynamic": {mode: VerifyStrict, dynamic: true},
	}

	for name, tc := range modes {
		t.Run(name, func(t *testing.T) {
			certs := genChain(t)
			pool := x509.NewCertPool()
			pool.AddCert(certs.root)

			var rootCAs certPoolProvider = newStaticCertPool(pool)
			if tc.dynamic {
				rootCAs = &fakeDynamicPool{pool: pool}
			}
			cfg := &TLSConfig{
				Verification: tc.mode,
				ServerName:   "localhost",
				rootCAs:      rootCAs,
			}
			cs := tls.ConnectionState{PeerCertificates: peerCerts(certs)}

			require.NoError(t, makeVerifyConnection(cfg, logger)(cs),
				"chain through a trusted root must verify before the key is distrusted")

			distrustForTest(t, certs.intermediate)
			err := makeVerifyConnection(cfg, logger)(cs)
			require.ErrorIs(t, err, ErrDistrustedKey,
				"chain through a distrusted intermediate must be rejected even if the root is trusted")
		})
	}

	t.Run("strict static uses Go's verified chains", func(t *testing.T) {
		certs := genChain(t)
		pool := x509.NewCertPool()
		pool.AddCert(certs.root)
		cfg := &TLSConfig{
			Verification: VerifyStrict,
			ServerName:   "localhost",
			rootCAs:      newStaticCertPool(pool),
		}
		// With static CAs the TLS stack has already built VerifiedChains.
		cs := tls.ConnectionState{
			PeerCertificates: peerCerts(certs),
			VerifiedChains: [][]*x509.Certificate{
				{certs.leaf, certs.intermediate, certs.root},
			},
		}

		require.NoError(t, makeVerifyConnection(cfg, logger)(cs),
			"verified chain must be accepted before the key is distrusted")

		distrustForTest(t, certs.intermediate)
		require.ErrorIs(t, makeVerifyConnection(cfg, logger)(cs), ErrDistrustedKey,
			"verified chain through a distrusted intermediate must be rejected")
	})

	t.Run("strict static with CA pin on a clean chain", func(t *testing.T) {
		certs := genChain(t)
		distrustForTest(t, certs.intermediate)

		clean, err := tlscommontest.GenCA()
		require.NoError(t, err, "generating clean CA")
		pool := x509.NewCertPool()
		pool.AddCert(certs.root)
		pool.AddCert(clean.Leaf)
		cfg := &TLSConfig{
			Verification: VerifyStrict,
			ServerName:   "localhost",
			rootCAs:      newStaticCertPool(pool),
			CASha256:     []string{Fingerprint(clean.Leaf)},
		}
		cs := tls.ConnectionState{
			PeerCertificates: peerCerts(certs),
			VerifiedChains: [][]*x509.Certificate{
				{certs.leaf, certs.intermediate, certs.root},
				{certs.leaf, clean.Leaf},
			},
		}

		require.NoError(t, makeVerifyConnection(cfg, logger)(cs),
			"a second chain free of distrusted keys that matches the pin must be accepted")

		cfg.CASha256 = []string{Fingerprint(certs.root)}
		require.ErrorIs(t, makeVerifyConnection(cfg, logger)(cs), ErrCAPinMissmatch,
			"a pin that only matches the distrusted chain must not be satisfied by it")
	})
}

// TestVerifyServerConnectionDistrustedIntermediate checks that client
// certificates issued by a distrusted intermediate are rejected on the server
// side too.
func TestVerifyServerConnectionDistrustedIntermediate(t *testing.T) {
	for name, mode := range map[string]TLSVerificationMode{
		"full":        VerifyFull,
		"certificate": VerifyCertificate,
	} {
		t.Run(name, func(t *testing.T) {
			certs := genChain(t)
			pool := x509.NewCertPool()
			pool.AddCert(certs.root)
			cfg := &TLSConfig{
				Verification: mode,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				clientCAs:    newStaticCertPool(pool),
			}
			cs := tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{certs.leaf, certs.intermediate},
			}

			require.NoError(t, makeVerifyServerConnection(cfg)(cs),
				"client chain through a trusted root must verify before the key is distrusted")

			distrustForTest(t, certs.intermediate)
			require.ErrorIs(t, makeVerifyServerConnection(cfg)(cs), ErrDistrustedKey,
				"client chain through a distrusted intermediate must be rejected")
		})
	}

	t.Run("strict static uses Go's verified chains", func(t *testing.T) {
		certs := genChain(t)
		pool := x509.NewCertPool()
		pool.AddCert(certs.root)
		cfg := &TLSConfig{
			Verification: VerifyStrict,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			clientCAs:    newStaticCertPool(pool),
		}
		cs := tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certs.leaf, certs.intermediate},
			VerifiedChains: [][]*x509.Certificate{
				{certs.leaf, certs.intermediate, certs.root},
			},
		}

		require.NoError(t, makeVerifyServerConnection(cfg)(cs),
			"verified client chain must be accepted before the key is distrusted")

		distrustForTest(t, certs.intermediate)
		require.ErrorIs(t, makeVerifyServerConnection(cfg)(cs), ErrDistrustedKey,
			"verified client chain through a distrusted intermediate must be rejected")

		cfg.CASha256 = []string{Fingerprint(certs.root)}
		require.ErrorIs(t, makeVerifyServerConnection(cfg)(cs), ErrDistrustedKey,
			"the distrusted key check must run before the CA pin check")
	})
}

// TestHandshakeRejectsDistrustedIntermediate runs real handshakes against a
// server whose certificate is issued by a distrusted intermediate, using the
// tls.Config that tlscommon hands to callers. It covers both the modes where
// tlscommon verifies the chain itself and strict mode where Go does.
func TestHandshakeRejectsDistrustedIntermediate(t *testing.T) {
	for name, mode := range map[string]TLSVerificationMode{
		"full":        VerifyFull,
		"certificate": VerifyCertificate,
		"strict":      VerifyStrict,
	} {
		t.Run(name, func(t *testing.T) {
			certs := genChain(t)
			pool := x509.NewCertPool()
			pool.AddCert(certs.root)
			cfg := &TLSConfig{
				Verification: mode,
				rootCAs:      newStaticCertPool(pool),
				Logger:       logptest.NewTestingLogger(t, ""),
			}

			require.NoError(t, handshake(t, certs.serverCert, cfg.BuildModuleClientConfig("localhost")),
				"handshake must succeed before the intermediate key is distrusted")

			distrustForTest(t, certs.intermediate)
			err := handshake(t, certs.serverCert, cfg.BuildModuleClientConfig("localhost"))
			require.ErrorIs(t, err, ErrDistrustedKey,
				"handshake through a distrusted intermediate must fail even though the root is trusted")
		})
	}

	t.Run("none skips the check", func(t *testing.T) {
		certs := genChain(t)
		distrustForTest(t, certs.intermediate)
		cfg := &TLSConfig{
			Verification: VerifyNone,
			Logger:       logptest.NewTestingLogger(t, ""),
		}

		// Verification is disabled on purpose, so there is no chain to check.
		require.NoError(t, handshake(t, certs.serverCert, cfg.BuildModuleClientConfig("localhost")),
			"verification_mode none must not reject distrusted keys")
	})
}

// fakeDynamicPool is a certPoolProvider that reports itself as dynamic, which
// makes VerifyStrict verify the chain itself instead of relying on Go.
type fakeDynamicPool struct {
	pool *x509.CertPool
}

func (f *fakeDynamicPool) GetCertPool() *x509.CertPool           { return f.pool }
func (f *fakeDynamicPool) AddTrustedCert(cert *x509.Certificate) { f.pool.AddCert(cert) }
func (f *fakeDynamicPool) IsDynamic() bool                       { return true }

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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// checkPeerCertsFIPS rejects any certificate in the chain whose public key is
// not approved by FIPS 140-3. It must be called explicitly from VerifyConnection
// because Go's built-in FIPS certificate check is skipped whenever
// InsecureSkipVerify=true — which most of our verification modes require.
//
// TODO: Go does not yet expose a public API for this check. If one is added
// (tracked in https://github.com/golang/go/issues/80074), replace this with
// the standard library call so we stop maintaining a local copy.
func checkPeerCertsFIPS(certs []*x509.Certificate) error {
	for _, cert := range certs {
		if !isCertAllowedFIPS(cert) {
			return fmt.Errorf("tls: certificate uses %T public key which is not allowed by FIPS 140-3", cert.PublicKey)
		}
	}
	return nil
}

// isCertAllowedFIPS reports whether cert uses a FIPS 140-3 approved key:
// RSA ≥ 2048 bits, ECDSA on P-256/P-384/P-521, or Ed25519.
// The allowed ECDSA curves mirror the TLS key-exchange curve allowlist in types_fips.go.
// If that list changes, update this function to match.
func isCertAllowedFIPS(cert *x509.Certificate) bool {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return true
	default:
		return false
	}
}
